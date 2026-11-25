// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import "testing"

// TestServeConfigExamples spells each row the three ways a user meets it: the
// tailscale serve commands, the file get-config --all writes for them, and
// serve status --json. Both the commands and that file applied with
// set-config --all on a fresh node must read out as the row says, so what
// set-config reads is what get-config writes. A file that round-trips to
// itself can still name the wrong listener; serve status --json shows the
// one actually served.
func TestServeConfigExamples(t *testing.T) {
	tests := []struct {
		name   string
		cli    []string // tailscale serve ...
		config string   // tailscale serve get-config --all
		status string   // tailscale serve status --json
	}{
		// A string endpoint's scheme names both the listener and the back-end.
		{
			name: "http_to_http",
			cli:  []string{"--service=svc:awesome --http=80 127.0.0.1:30123"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:80": "http://127.0.0.1:30123"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "80": {
				          "HTTP": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:80": {
				          "Handlers": {
				            "/": {
				              "Proxy": "http://127.0.0.1:30123"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "https_to_https",
			cli:  []string{"--service=svc:awesome --https=443 https://127.0.0.1:8443"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": "https://127.0.0.1:8443"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTPS": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Proxy": "https://127.0.0.1:8443"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			// The case from #18381: HTTPS in front of plain HTTP, which no
			// string says, so the endpoint is an object naming the listener.
			name: "https_to_http",
			cli:  []string{"--service=svc:awesome --https=443 127.0.0.1:30123"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": {
				          "front": "https",
				          "backend": "http://127.0.0.1:30123"
				        }
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTPS": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Proxy": "http://127.0.0.1:30123"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			// The string older clients wrote for the row above keeps the
			// meaning it always had: plaintext HTTP on port 443.
			name: "http_on_443",
			cli:  []string{"--service=svc:awesome --http=443 127.0.0.1:30123"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": "http://127.0.0.1:30123"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTP": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Proxy": "http://127.0.0.1:30123"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "http_to_https",
			cli:  []string{"--service=svc:awesome --http=80 https://127.0.0.1:8443"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:80": {
				          "front": "http",
				          "backend": "https://127.0.0.1:8443"
				        }
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "80": {
				          "HTTP": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:80": {
				          "Handlers": {
				            "/": {
				              "Proxy": "https://127.0.0.1:8443"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			// file:// is served over HTTPS.
			name: "https_to_file",
			cli:  []string{"--service=svc:awesome --https=443 $DIR/index.html"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": "file://$DIR/index.html"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTPS": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Path": "$DIR/index.html"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			// tailscaled speaks plain HTTP to a Unix socket, so the scheme
			// names only the listener.
			name: "https_to_unix_socket",
			cli:  []string{"--service=svc:awesome --https=443 unix:/run/app.sock"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": "https://unix:/run/app.sock"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTPS": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Proxy": "unix:/run/app.sock"
				            }
				          }
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "tcp",
			cli:  []string{"--service=svc:awesome --tcp=5432 tcp://127.0.0.1:5432"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:5432": "tcp://127.0.0.1:5432"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "5432": {
				          "TCPForward": "127.0.0.1:5432"
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "tls_terminated_tcp",
			cli:  []string{"--service=svc:awesome --tls-terminated-tcp=443 tcp://127.0.0.1:9481"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": "tls-terminated-tcp://127.0.0.1:9481"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "TCPForward": "127.0.0.1:9481",
				          "TerminateTLS": "awesome.test.ts.net"
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "tun",
			cli:  []string{"--service=svc:awesome --tun"},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "*": "TUN"
				      }
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "Tun": true
				    }
				  }
				}`,
		},
		{
			// serve status --json does not show advertisement, so only the
			// file says the Service is drained.
			name: "drained",
			cli: []string{
				"--service=svc:awesome --tcp=5432 tcp://127.0.0.1:5432",
				"drain svc:awesome",
			},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:5432": "tcp://127.0.0.1:5432"
				      },
				      "advertised": false
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "5432": {
				          "TCPForward": "127.0.0.1:5432"
				        }
				      }
				    }
				  }
				}`,
		},
		{
			name: "two_services",
			cli: []string{
				"--service=svc:awesome --https=443 127.0.0.1:30123",
				"--service=svc:db --tcp=5432 tcp://127.0.0.1:5432",
				"drain svc:db",
			},
			config: `
				{
				  "version": "0.0.1",
				  "services": {
				    "svc:awesome": {
				      "endpoints": {
				        "tcp:443": {
				          "front": "https",
				          "backend": "http://127.0.0.1:30123"
				        }
				      }
				    },
				    "svc:db": {
				      "endpoints": {
				        "tcp:5432": "tcp://127.0.0.1:5432"
				      },
				      "advertised": false
				    }
				  }
				}`,
			status: `
				{
				  "Services": {
				    "svc:awesome": {
				      "TCP": {
				        "443": {
				          "HTTPS": true
				        }
				      },
				      "Web": {
				        "awesome.test.ts.net:443": {
				          "Handlers": {
				            "/": {
				              "Proxy": "http://127.0.0.1:30123"
				            }
				          }
				        }
				      }
				    },
				    "svc:db": {
				      "TCP": {
				        "5432": {
				          "TCPForward": "127.0.0.1:5432"
				        }
				      }
				    }
				  }
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipOnWindows(t, tt.cli...)
			dir := serveTestDir(t)
			config, status := expandDir(tt.config, dir), expandDir(tt.status, dir)

			// cli -> get-config == config, status == status
			cliNode := buildState(t, dir, tt.cli)
			checkJSON(t, "get-config --all after the commands", config, runServeCmd(t, cliNode, "get-config", "--all"))
			checkJSON(t, "serve status --json after the commands", status, runServeCmd(t, cliNode, "status", "--json"))

			// set-config(config) -> get-config == config, status == status
			fileNode := newServiceHostClient()
			setConfig(t, fileNode, "--all", config)
			checkJSON(t, "get-config --all after set-config --all of config", config, runServeCmd(t, fileNode, "get-config", "--all"))
			checkJSON(t, "serve status --json after set-config --all of config", status, runServeCmd(t, fileNode, "status", "--json"))
		})
	}
}

// TestServeConfigIssue18381 replays the steps of #18381 on one node: a
// Service exported with get-config and imported with set-config after a reset
// comes back serving HTTPS, as it was, not plaintext HTTP on port 443.
func TestServeConfigIssue18381(t *testing.T) {
	const servingHTTPS = `
		{
		  "Services": {
		    "svc:awesome": {
		      "TCP": {
		        "443": {
		          "HTTPS": true
		        }
		      },
		      "Web": {
		        "awesome.test.ts.net:443": {
		          "Handlers": {
		            "/": {
		              "Proxy": "http://127.0.0.1:30123"
		            }
		          }
		        }
		      }
		    }
		  }
		}`
	node := newServiceHostClient()

	// 1. Register a service with TLS.
	runServeCmd(t, node, cmd("--service=svc:awesome --https=443 127.0.0.1:30123")...)
	checkJSON(t, "1. serve status --json", servingHTTPS, runServeCmd(t, node, "status", "--json"))

	// 2. Export service config to a file.
	services := runServeCmd(t, node, "get-config", "--all")
	checkJSON(t, "2. get-config --all", `
		{
		  "version": "0.0.1",
		  "services": {
		    "svc:awesome": {
		      "endpoints": {
		        "tcp:443": {
		          "front": "https",
		          "backend": "http://127.0.0.1:30123"
		        }
		      }
		    }
		  }
		}`, services)

	// 3. Reset serve config.
	runServeCmd(t, node, "reset")
	checkJSON(t, "3. serve status --json after reset", `{}`, runServeCmd(t, node, "status", "--json"))

	// 4. Import the file.
	runServeCmd(t, node, "set-config", "--all", writeTmpServeConfig(t, services))
	checkJSON(t, "4. serve status --json after set-config --all", servingHTTPS, runServeCmd(t, node, "status", "--json"))
}
