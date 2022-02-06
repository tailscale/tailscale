// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build aix darwin dragonfly freebsd nacl netbsd openbsd solaris

package rand

var defaultContextReader = &urandomReader{}
