# seHTTPd

`seHTTPd` implements a small and efficient web server with 1K lines of C code.
I/O multiplexing is achieved using [epoll](http://man7.org/linux/man-pages/man7/epoll.7.html).

```text
+----------------------------------------------+
|                                              |
|  +-----------+   wait   +-----------------+  |  copy   +---------+
|  |           +---------->                 +------------>         |
|  | IO Device |    1     | Kernel's buffer |  |   2     | Process |
|  |           <----------+                 <------------+         |
|  +-----------+          +-----------------+  |         +---------+
|                                              |
+----------------------------------------------+
```

## License
`seHTTPd` is released under the MIT License. Use of this source code is governed
by a MIT License that can be found in the LICENSE file.
