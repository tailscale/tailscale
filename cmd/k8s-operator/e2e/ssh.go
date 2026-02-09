// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tailscaleroot "tailscale.com"
	"tailscale.com/types/ptr"
)

const (
	keysFilePath = "/root/.ssh/authorized_keys"
	sshdConfig   = `
Port 8022

# Allow reverse tunnels
GatewayPorts yes
AllowTcpForwarding yes

# Auth
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile ` + keysFilePath
)

var privateKeyPath = filepath.Join(tmp, "id_ed25519")

func connectClusterToDevcontrol(ctx context.Context, logger *zap.SugaredLogger, cl client.WithWatch, restConfig *rest.Config, privKey ed25519.PrivateKey, pubKey []byte) (clusterIP string, _ error) {
	logger.Info("Setting up SSH reverse tunnel from cluster to devcontrol...")
	var err error
	if clusterIP, err = applySSHResources(ctx, cl, tailscaleroot.AlpineDockerTag, pubKey); err != nil {
		return "", fmt.Errorf("failed to apply ssh-server resources: %w", err)
	}
	sshPodName, err := waitForPodReady(ctx, logger, cl, ns, client.MatchingLabels{"app": "ssh-server"})
	if err != nil {
		return "", fmt.Errorf("ssh-server Pod not ready: %w", err)
	}
	if err := forwardLocalPortToPod(ctx, logger, restConfig, ns, sshPodName, 8022); err != nil {
		return "", fmt.Errorf("failed to set up port forwarding to ssh-server: %w", err)
	}
	if err := reverseTunnel(ctx, logger, privKey, fmt.Sprintf("localhost:%d", 8022), 31544, "localhost:31544"); err != nil {
		return "", fmt.Errorf("failed to set up reverse tunnel: %w", err)
	}

	return clusterIP, nil
}

func reverseTunnel(ctx context.Context, logger *zap.SugaredLogger, privateKey ed25519.PrivateKey, sshHost string, remotePort uint16, fwdTo string) error {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	logger.Infof("Connected to SSH server at %s\n", sshHost)

	go func() {
		defer conn.Close()

		// Start listening on remote port.
		remoteAddr := fmt.Sprintf("localhost:%d", remotePort)
		remoteLn, err := conn.Listen("tcp", remoteAddr)
		if err != nil {
			logger.Infof("Failed to listen on remote port %d: %v", remotePort, err)
			return
		}
		defer remoteLn.Close()
		logger.Infof("Reverse tunnel ready on remote addr %s -> local addr %s", remoteAddr, fwdTo)

		for {
			remoteConn, err := remoteLn.Accept()
			if err != nil {
				logger.Infof("Failed to accept remote connection: %v", err)
				return
			}

			go handleConnection(ctx, logger, remoteConn, fwdTo)
		}
	}()

	return nil
}

func handleConnection(ctx context.Context, logger *zap.SugaredLogger, remoteConn net.Conn, fwdTo string) {
	go func() {
		<-ctx.Done()
		remoteConn.Close()
	}()

	var d net.Dialer
	localConn, err := d.DialContext(ctx, "tcp", fwdTo)
	if err != nil {
		logger.Infof("Failed to connect to local service %s: %v", fwdTo, err)
		return
	}
	go func() {
		<-ctx.Done()
		localConn.Close()
	}()

	go func() {
		if _, err := io.Copy(localConn, remoteConn); err != nil {
			logger.Infof("Error copying remote->local: %v", err)
		}
	}()

	go func() {
		if _, err := io.Copy(remoteConn, localConn); err != nil {
			logger.Infof("Error copying local->remote: %v", err)
		}
	}()
}

func readOrGenerateSSHKey(tmp string) (ed25519.PrivateKey, []byte, error) {
	var privateKey ed25519.PrivateKey
	b, err := os.ReadFile(privateKeyPath)
	switch {
	case os.IsNotExist(err):
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate key: %w", err)
		}
		privKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal SSH private key: %w", err)
		}
		f, err := os.OpenFile(privateKeyPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open SSH private key file: %w", err)
		}
		defer f.Close()
		if err := pem.Encode(f, privKeyPEM); err != nil {
			return nil, nil, fmt.Errorf("failed to write SSH private key: %w", err)
		}
	case err != nil:
		return nil, nil, fmt.Errorf("failed to read SSH private key: %w", err)
	default:
		pKey, err := ssh.ParseRawPrivateKey(b)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse SSH private key: %w", err)
		}
		pKeyPointer, ok := pKey.(*ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("SSH private key is not ed25519: %T", pKey)
		}
		privateKey = *pKeyPointer
	}

	sshPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}

	return privateKey, ssh.MarshalAuthorizedKey(sshPublicKey), nil
}

func applySSHResources(ctx context.Context, cl client.Client, alpineTag string, pubKey []byte) (string, error) {
	owner := client.FieldOwner("k8s-test")

	if err := cl.Patch(ctx, sshDeployment(alpineTag, pubKey), client.Apply, owner); err != nil {
		return "", fmt.Errorf("failed to apply ssh-server Deployment: %w", err)
	}
	if err := cl.Patch(ctx, sshConfigMap(pubKey), client.Apply, owner); err != nil {
		return "", fmt.Errorf("failed to apply ssh-server ConfigMap: %w", err)
	}
	svc := sshService()
	if err := cl.Patch(ctx, svc, client.Apply, owner); err != nil {
		return "", fmt.Errorf("failed to apply ssh-server Service: %w", err)
	}

	return svc.Spec.ClusterIP, nil
}

func cleanupSSHResources(ctx context.Context, cl client.Client) error {
	noGrace := &client.DeleteOptions{
		GracePeriodSeconds: ptr.To[int64](0),
	}
	if err := cl.Delete(ctx, sshDeployment("", nil), noGrace); err != nil {
		return fmt.Errorf("failed to delete ssh-server Deployment: %w", err)
	}
	if err := cl.Delete(ctx, sshConfigMap(nil), noGrace); err != nil {
		return fmt.Errorf("failed to delete ssh-server ConfigMap: %w", err)
	}
	if err := cl.Delete(ctx, sshService(), noGrace); err != nil {
		return fmt.Errorf("failed to delete control Service: %w", err)
	}

	return nil
}

func sshDeployment(tag string, pubKey []byte) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ssh-server",
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "ssh-server",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "ssh-server",
					},
					Annotations: map[string]string{
						"pubkey": hex.EncodeToString(pubKey), // Ensure new key triggers rollout.
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "ssh-server",
							Image: fmt.Sprintf("alpine:%s", tag),
							Command: []string{
								"sh", "-c",
								"apk add openssh-server; ssh-keygen -A; /usr/sbin/sshd -D -e",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "ctrl-port-fwd",
									ContainerPort: 31544,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "ssh",
									ContainerPort: 8022,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(8022),
									},
								},
								InitialDelaySeconds: 1,
								PeriodSeconds:       1,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "sshd-config",
									MountPath: "/etc/ssh/sshd_config.d/reverse-tunnel.conf",
									SubPath:   "reverse-tunnel.conf",
								},
								{
									Name:      "sshd-config",
									MountPath: keysFilePath,
									SubPath:   "authorized_keys",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "sshd-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "ssh-server-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func sshConfigMap(pubKey []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ssh-server-config",
			Namespace: ns,
		},
		Data: map[string]string{
			"reverse-tunnel.conf": sshdConfig,
			"authorized_keys":     string(pubKey),
		},
	}
}

func sshService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "control",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": "ssh-server",
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "tunnel",
					Port:     31544,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}
