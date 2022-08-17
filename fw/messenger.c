/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2022, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>
#include <ti/drivers/UART2.h>
#include "ti_drivers_config.h"
#include "messenger.h"
#include "base64.h"

UART2_Handle uart;

int messenger_init()
{
    UART2_Params uartParams;
    UART2_Params_init(&uartParams);
    uartParams.baudRate = 2000000;
    uart = UART2_open(CONFIG_UART2_0, &uartParams);
    if (!uart)
        return -1;

    return 0;
}

// keep doing small inefficient reads till we hit a CRLF
static void _recv_crlf()
{
    bool done = false;
    uint8_t b = 0;
    size_t bytes_read;

    while (!done)
    {
        UART2_read(uart, &b, 1, &bytes_read);
        while (b == '\r')
        {
            UART2_read(uart, &b, 1, &bytes_read);
            if (b == '\n')
                done = true;
        }
    }
}

// this function is NOT reentrant!
int messenger_recv(uint8_t *dst_buf)
{
    uint32_t dec_len;
    int word_cnt, last_byte, dec_stat;
    size_t bytes_read;

    // 2 bytes for CRLF
    static uint8_t b64_buf[((MESSAGE_MAX * 4) / 3) + 2];

    // first byte of b64 decoded data indicates number of 4 byte chunks
    // read 2 extra bytes for CRLF
    UART2_read(uart, b64_buf, 6, &bytes_read);

    dec_len = base64_decode(dst_buf, b64_buf, 4, &dec_stat);
    if (dec_stat < 0)
    {
        _recv_crlf();
        return -1;
    }

    word_cnt = dst_buf[0];
    if (word_cnt > (MESSAGE_MAX >> 2))
    {
        // too big or some sync issue
        _recv_crlf();
        return -2;
    }

    if (word_cnt > 1)
    {
        UART2_read(uart, b64_buf + 6, (word_cnt - 1) << 2, &bytes_read);
    }

    // make sure CRLF terminator is present
    last_byte = word_cnt << 2;
    if (b64_buf[last_byte] != '\r' || b64_buf[last_byte + 1] != '\n')
    {
        // malformed data/sync error
        _recv_crlf();
        return -3;
    }

    // convert to binary
    dec_len = base64_decode(dst_buf, b64_buf, last_byte, &dec_stat);
    if (dec_stat < 0)
    {
        // malfored data/sync error
        _recv_crlf();
        return dec_stat - 10;
    }

    // return length of received message
    return dec_len;
}

void messenger_send(const uint8_t *src_buf, unsigned src_len)
{
    uint32_t enc_len, bytes_remaining, bytes_sent;

    // 2 bytes for CRLF
    static uint8_t b64_buf[((MESSAGE_MAX * 4) / 3) + 2];

    enc_len = base64_encode(b64_buf, src_buf, src_len);
    b64_buf[enc_len] = '\r';
    b64_buf[enc_len + 1] = '\n';

    bytes_remaining = enc_len + 2; // two byte CRLF
    bytes_sent = 0;
    while (bytes_remaining)
    {
        // sometimes, even in blocking mode, UART_write returns before the
        // complete buffer was sent, due to some queues being full
        size_t sent;
        UART2_write(uart, b64_buf + bytes_sent, bytes_remaining, &sent);
        bytes_remaining -= sent;
        bytes_sent += sent;
    }
}
