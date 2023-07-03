#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
// #include <openssl/pem.h>
#include <picotls.h>
#include <picotls/minicrypto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* raw private key and certificate using secp256v1 */
#define SECP256R1_PRIVATE_KEY                                                                                          \
    "\xc1\x74\xb4\xf9\x5e\xfe\x7a\x01\x0e\xbe\x4a\xe8\x33\xb2\x36\x13\xfc\x65\xe9\x65\x91\xa8\x39\x9e\x9a\x80\xfb\xab" \
    "\xd1\xff\xba"                                                                                                     \
    "\x3a"
#define SECP256R1_CERTIFICATE                                                                                          \
    "\x30\x82\x02\x60\x30\x82\x01\x48\xa0\x03\x02\x01\x02\x02\x01\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" \
    "\x0b\x05\x00"                                                                                                     \
    "\x30\x1a\x31\x18\x30\x16\x06\x03\x55\x04\x03\x13\x0f\x70\x69\x63\x6f\x74\x6c\x73\x20\x74\x65\x73\x74\x20\x63\x61" \
    "\x30\x1e\x17"                                                                                                     \
    "\x0d\x31\x38\x30\x32\x32\x33\x30\x35\x33\x31\x30\x34\x5a\x17\x0d\x32\x38\x30\x32\x32\x31\x30\x35\x33\x31\x30\x34" \
    "\x5a\x30\x1b"                                                                                                     \
    "\x31\x19\x30\x17\x06\x03\x55\x04\x03\x13\x10\x74\x65\x73\x74\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30" \
    "\x59\x30\x13"                                                                                                     \
    "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\xda\xc8\xa5\x40\x54" \
    "\xba\x33\xda"                                                                                                     \
    "\x18\xa9\x41\x7f\x49\x53\xdf\x60\xe6\xa6\x3d\xb6\x8e\x53\x3a\x9f\xdd\x19\x14\x5e\xab\x03\xcf\xbc\xfb\x36\x98\x16" \
    "\x24\x8f\x07"                                                                                                     \
    "\x29\x6d\x15\xd8\x4f\x30\xe8\x09\x64\xfb\x14\xfc\x86\x7c\xd4\x06\xc2\xfd\x9d\xe8\x99\x3f\x48\x8c\x2b\xa3\x7b\x30" \
    "\x79\x30\x09"                                                                                                     \
    "\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x2c\x06\x09\x60\x86\x48\x01\x86\xf8\x42\x01\x0d\x04\x1f\x16\x1d\x4f\x70" \
    "\x65\x6e\x53"                                                                                                     \
    "\x53\x4c\x20\x47\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x30\x1d\x06\x03" \
    "\x55\x1d\x0e"                                                                                                     \
    "\x04\x16\x04\x14\xee\x30\x86\x16\xa1\xd2\x69\xad\x64\xe4\xd7\x77\x6b\xb2\xfd\x5c\x4f\x01\xa2\xb5\x30\x1f\x06\x03" \
    "\x55\x1d\x23"                                                                                                     \
    "\x04\x18\x30\x16\x80\x14\xbf\x79\xca\x97\xb2\x60\x78\x20\x96\xaa\x46\x57\x9c\xdf\xa7\xb2\x23\xf5\x25\x63\x30\x0d" \
    "\x06\x09\x2a"                                                                                                     \
    "\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x8f\xac\x9c\x01\x6d\x81\xaa\x8c\xae\x5d\xb5\x16\x74" \
    "\xea\xe8\xeb"                                                                                                     \
    "\x26\x5b\xb1\x66\xd5\x6b\xd4\x4d\x79\x0d\x6d\x87\xa9\xb6\xbf\x74\x2d\xc1\xb2\x2e\x52\xb6\x4b\xca\x0d\x01\x45\x38" \
    "\x58\x1a\xd2"                                                                                                     \
    "\x6a\x6d\x20\x98\x5a\x51\xb0\x6f\x2c\x3f\x0f\x12\x88\xed\x7c\x09\xa5\x74\x00\x21\x3d\x4b\xd2\x2d\x54\xaa\x53\x8b" \
    "\x64\xf9\x1e"                                                                                                     \
    "\xea\xa5\x8a\xe7\x61\x5e\x56\x92\x52\x36\x3e\xa0\x68\x59\x9c\x7d\xb3\xe8\x5c\x4b\x77\x6e\xde\x28\xed\x18\x91\xa9" \
    "\x9c\x39\xd2"                                                                                                     \
    "\x96\xcc\x98\x05\x8c\x74\xdc\x1e\x12\x5b\x38\xbd\x56\xcb\xa3\xe8\xe1\x2a\x5a\x2b\xd2\x32\x45\xc1\x10\x85\x20\x6c" \
    "\x6b\x34\xea"                                                                                                     \
    "\x66\x91\x0e\x2e\xb8\x64\x87\x9f\x07\xbc\x23\x4f\x23\xad\xbe\x89\xdf\x0a\x98\x47\xe9\x63\x02\xd3\x41\xf4\x2d\xa4" \
    "\xce\xdd\xe3"                                                                                                     \
    "\xd8\x41\x08\xfe\xdf\x47\xc0\xe7\x63\x8e\x1f\xf0\x4b\xc5\xae\xab\xc0\xba\x38\x3e\xe3\x90\x9c\x08\xbd\x75\x1c\xb9" \
    "\xb8\x54\x43"                                                                                                     \
    "\x1d\x99\x42\xe0\xa2\xb7\x75\xbb\x14\x03\x79\x9a\xf6\x07\xd8\xa5\xab\x2b\x3a\x70\x8b\x77\x85\x70\x8a\x98\x38\x9b" \
    "\x35\x09\xf6"                                                                                                     \
    "\x62\x6b\x29\x4a\xa7\xa7\xf9\x3b\xde\xd8\xc8\x90\x57\xf2\x76\x2a\x23\x0b\x01\x68\xc6\x9a\xf2"

ptls_context_t* ctx = NULL;
ptls_handshake_properties_t* hsprop = NULL;
const int signals_list[] = {SIGINT, SIGTERM};

int read_cert(ptls_iovec_t* certificate) {
    // FILE* fp;

    // if ((fp = fopen(CERT_PATH, "r")) == NULL) {
    //     fprintf(stderr, "Failed to open certificate file at %s\n", CERT_PATH);
    //     return -1;
    // }

    // X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);

    // certificate->len = i2d_X509(cert, &certificate->base);
    // certificate = ptls_iovec_init();

    // fclose(fp);
    // if (ctx->certificates.count == 0) {
    //     fprintf(stderr, "Failed to load certificates from file at %s\n", CERT_PATH);
    //     return -1;
    // }
    *certificate = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);
    return 0;
}

int read_pkey(ptls_minicrypto_secp256r1sha256_sign_certificate_t* sign_certificate) {
    // FILE* fp;

    // if ((fp = fopen(PKEY_PATH, "r")) == NULL) {
    //     fprintf(stderr, "Failed to open private key file at %s\n", PKEY_PATH);
    //     return -1;
    // }

    // EC_KEY* pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

    // fclose(fp);

    // if (pkey == NULL) {
    //     fprintf(stderr, "Failed to load private key from file at %s\n", PKEY_PATH);
    //     return -1;
    // }
    // ptls_iovec_t pkey_iovec;
    // pkey_iovec.len = i2d_ECPrivateKey(pkey, &pkey_iovec.base);
    int rv = ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, SECP256R1_PRIVATE_KEY_SIZE));
    // EC_KEY_free(pkey);
    // if (rv)
    //     fprintf(stderr, "Failed to sign private key from file at %s -> %li\n", PKEY_PATH, pkey_iovec.len);
    // return rv;
    return 0;
}

int resolve_address(struct sockaddr* sa, socklen_t* salen, const char* host, const char* port) {
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;

    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "Failed to resolve address '%s:%s': %s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL\n");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int write_all(int fd, const uint8_t* data, size_t len) {
    ssize_t wret;
    while (len != 0) {
        while ((wret = write(fd, data, len)) == -1 && errno == EINTR)
            ;
        if (wret <= 0) {
            fprintf(stderr, "Write to %d failed.\n", fd);
            return -1;
        }
        data += wret;
        len -= wret;
    }
    return 0;
}

int do_handshake(int fd, ptls_t* tls, ptls_buffer_t* wbuf, char* rbuf, size_t* rbuf_len,
                 ptls_handshake_properties_t* hsprop, ptls_iovec_t unused) {
    size_t input_len = *rbuf_len;
    int ret;
    ssize_t rret = 0;
    *rbuf_len = 0;

    while ((ret = ptls_handshake(tls, wbuf, rbuf, rbuf_len, hsprop)) == PTLS_ERROR_IN_PROGRESS) {
        if (write_all(fd, wbuf->base, wbuf->off) != 0)
            return -1;
        wbuf->off = 0;

        while ((rret = read(fd, rbuf, input_len)) == -1 && errno == EINTR)
            ;

        if (rret < 0) {
            perror("Read from client failed");
            return -1;
        }
        *rbuf_len = rret;
    }

    if (ret != PTLS_ALERT_CLOSE_NOTIFY) {
        fprintf(stderr, "Handshake failed with error code %d.\n", ret);
        return -1;
    }

    if (write_all(fd, wbuf->base, wbuf->off) != 0)
        return -1;

    if (rret != *rbuf_len)
        memmove(rbuf, rbuf + *rbuf_len, rret - *rbuf_len);
    *rbuf_len = rret - *rbuf_len;
    return 0;
}

int decrypt_and_print(ptls_t* tls, const uint8_t* input, size_t inlen) {
    ptls_buffer_t decryptbuf;
    uint8_t decryptbuf_small[1024];
    int ret;

    ptls_buffer_init(&decryptbuf, decryptbuf_small, sizeof(decryptbuf_small));
    while (inlen != 0) {
        size_t consumed = inlen;
        if ((ret = ptls_receive(tls, &decryptbuf, input, &consumed)) != 0) {
            fprintf(stderr, "Failed to decrypt: %d\n", ret);
            ret = -1;
            goto exit;
        }
        input += consumed;
        inlen -= consumed;
        if (decryptbuf.off != 0) {
            if (write_all(1, decryptbuf.base, decryptbuf.off) != 0) {
                ret = -1;
                goto exit;
            }
            decryptbuf.off = 0;
        }
    }
    ret = 0;
exit:
    ptls_buffer_dispose(&decryptbuf);
    return ret;
}

int handle_connection(int server, int client) {
    int rv = 0;
    char rbuf[4096], wbuf_small[4096];
    ptls_buffer_t wbuf;
    // printf("Connection received\n");

    ptls_t* tls = ptls_new(ctx, 1);
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));

    size_t rbuf_len = sizeof(rbuf);
    if (do_handshake(client, tls, &wbuf, rbuf, &rbuf_len, hsprop, (ptls_iovec_t){NULL, 0}) != 0) {
        rv = -1;
        goto exit;
    }
    wbuf.off = 0;

    rbuf_len = recv(client, rbuf, 4096, 0);

    if (decrypt_and_print(tls, (const uint8_t*)rbuf, rbuf_len) != 0) {
        rv = -1;
        goto exit;
    }

    // Send a message to the client:
    if ((rv = ptls_send(tls, &wbuf, "Hello, World!\n", strlen("Hello, World!\n"))) != 0) {
        fprintf(stderr, "Failed to encrypt message to client: %d\n", rv);
        rv = -1;
        goto exit;
    }

    if (write_all(client, wbuf.base, wbuf.off) != 0) {
        rv = -1;
        goto exit;
    }

exit:
    ptls_buffer_dispose(&wbuf);
    ptls_free(tls);
    return rv;
}

int run_server(struct sockaddr* sa, socklen_t sa_len) {
    int fd, on = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed");
        return -1;
    } else if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    } else if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
        return -1;
    } else if (bind(fd, sa, sa_len) != 0) {
        perror("bind(2) failed");
        return -1;
    } else if (listen(fd, SOMAXCONN) != 0) {
        perror("listen(2) failed");
        return -1;
    }

    fd_set active_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(fd, &active_fd_set);
    const int maxfd = fd;

    int rv = 0;
    while (1) {
        int sel_rv = select(maxfd + 1, &active_fd_set, NULL, NULL, NULL);
        if (sel_rv < 0) {
            if (errno == EINTR)
                break;
            else {
                perror("select failed");
                rv = -1;
                break;
            }
        }

        if (FD_ISSET(fd, &active_fd_set)) {
            int connection;
            if ((connection = accept(fd, NULL, 0)) != -1) {
                handle_connection(fd, connection);
                close(connection);
            }
        }
    }

    close(fd);
    return rv;
}

void signal_handler(int info) {}

int main(int argc, char* argv[]) {

    struct sockaddr_storage sa;
    socklen_t sa_len;
    ptls_iovec_t cert = {{NULL}};
    ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert = {{NULL}};
    ptls_handshake_properties_t h = {{{NULL}}};

    ptls_context_t c = {.random_bytes = ptls_minicrypto_random_bytes,
                        .get_time = &ptls_get_time,
                        .key_exchanges = ptls_minicrypto_key_exchanges,
                        .cipher_suites = ptls_minicrypto_cipher_suites,
                        .certificates = {&cert, 1},
                        .sign_certificate = &sign_cert.super};

    ctx = &c;
    hsprop = &h;

    // Setup signal handlers
    int i, rv = 0;
    for (i = 0; i < (sizeof(signals_list) / sizeof(int)); i++) {
        if (signal(signals_list[i], signal_handler) == SIG_ERR) {
            fprintf(stderr, "Failed to setup signal handlers\n");
            rv = -1;
        }
    }

    if (rv == 0)
        rv = read_cert(&cert);
    if (rv == 0)
        rv = read_pkey(&sign_cert);
    if (rv == 0)
        rv = resolve_address((struct sockaddr*)&sa, &sa_len, "127.0.0.1", "8000");
    if (rv == 0)
        rv = run_server((struct sockaddr*)&sa, sa_len);

    printf("\nProgram exited with code %d.\n", rv);
    return rv;
}