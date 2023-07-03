/* libtls_server.c */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <tls.h>

#include <err.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <tls.h>

int main(int argc, char *argv[]) {
  struct tls_config *cfg = NULL;
  struct tls *ctx = NULL, *cctx = NULL;
  uint8_t *mem;
  size_t mem_len;
  int clfd;
  ssize_t readlen;
  unsigned char buf[BUFSIZ];

  /*
  ** initialize libtls
  */

  if (tls_init() != 0)
    err(1, "tls_init:");

  /*
  ** configure libtls
  */

  if ((cfg = tls_config_new()) == NULL)
    err(1, "tls_config_new:");

  /* set root certificate (CA) */
  if ((mem = tls_load_file("./certs/cas.pem", &mem_len, NULL)) == NULL)
    err(1, "tls_load_file(ca):");
  if (tls_config_set_ca_mem(cfg, mem, mem_len) != 0)
    err(1, "tls_config_set_ca_mem:");

  /* set server certificate */
  if ((mem = tls_load_file("./certs/srv.crt", &mem_len, NULL)) == NULL)
    err(1, "tls_load_file(server):");
  if (tls_config_set_cert_mem(cfg, mem, mem_len) != 0)
    err(1, "tls_config_set_cert_mem:");

  /* set server private key */
  if ((mem = tls_load_file("./certs/main.key", &mem_len, NULL)) == NULL)
    err(1, "tls_load_file(serverkey):");
  if (tls_config_set_key_mem(cfg, mem, mem_len) != 0)
    err(1, "tls_config_set_key_mem:");

  /*
  ** initiate server context
  */

  if ((ctx = tls_server()) == NULL)
    err(1, "tls_server:");

  /*
  ** apply config to context
  */

  if (tls_configure(ctx, cfg) != 0)
    err(1, "tls_configure: %s", tls_error(ctx));

  /*
  ** create and accept socket
  */
  int sock, sock_ret;
  struct sockaddr_in addr;
  struct sockaddr_in client;
  int len;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    return (-1);

  bool const is_reusing = true;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    return (-1);

  if (listen(sock, 32) != 0)
    return (-1);

  len = sizeof(client);
  if (is_reusing) {
    // printf("setting up socket ...\n");
    if ((clfd = accept(sock, (struct sockaddr *)&client, (socklen_t *)&len)) <
        0)
      err(1, "setup_socket: %d", errno);

    // printf("accept socket ...\n");
    if (tls_accept_socket(ctx, &cctx, clfd) != 0)
      err(1, "tls_accept_socket: %s", tls_error(ctx));
  }
  while (true) {

    /*
    ** receive message from client
    */
    if (!is_reusing) {
      // printf("setting up socket ...\n");
      if ((clfd = accept(sock, (struct sockaddr *)&client, (socklen_t *)&len)) <
          0)
        err(1, "setup_socket: %d", errno);

      // printf("accept socket ...\n");
      if (tls_accept_socket(ctx, &cctx, clfd) != 0)
        err(1, "tls_accept_socket: %s", tls_error(ctx));
    }
    // printf("waiting message from client ...\n");
    if ((readlen = tls_read(cctx, buf, sizeof(buf))) < 0)
      err(1, "tls_read: %s", tls_error(cctx));
    tls_write(cctx, "HTTP/1.1 200 OK", 16);
    // printf("received message: [%*.*s]\n", readlen, readlen, buf);

    /*
    ** clean up all
    */

    if (!is_reusing) {
      if (tls_close(cctx) != 0)
        err(1, "tls_close: %s", tls_error(cctx));
      tls_free(cctx);
    }
  }

  if (is_reusing) {
    if (tls_close(cctx) != 0)
      err(1, "tls_close: %s", tls_error(cctx));
    tls_free(cctx);
  }
  tls_free(ctx);
  tls_config_free(cfg);

  return (0);
}