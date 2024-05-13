/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2024, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>
#include <ti/drivers/UART2.h>
#include "ti_drivers_config.h"
#include "ti_sysbios_config.h"
#include "messenger.h"
#include "base64.h"

UART2_Handle uart;

#ifdef UART_1M_BAUD
static const uint32_t BAUD_RATE = 921600;
#else
static const uint32_t BAUD_RATE = 2000000;
#endif

int messenger_init()
{
    UART2_Params uartParams;
    UART2_Params_init(&uartParams);
    uartParams.baudRate = BAUD_RATE;
    uartParams.readReturnMode = UART2_ReadReturnMode_FULL;
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
    UART2_read(uart, b64_buf, 1, &bytes_read);
    UART2_readTimeout(uart, b64_buf + 1, 5, &bytes_read,
            5000 / Clock_tickPeriod_D);
    if (bytes_read < 5)
    {
        // incomplete message
        _recv_crlf();
        return -1;
    }

    dec_len = base64_decode(dst_buf, b64_buf, 4, &dec_stat);
    if (dec_stat < 0)
    {
        // invalid characters
        _recv_crlf();
        return -2;
    }

    word_cnt = dst_buf[0];
    if (word_cnt * 3 > MESSAGE_MAX)
    {
        // too big or some sync issue
        _recv_crlf();
        return -3;
    }

    if (word_cnt > 1)
    {
        uint32_t bytes_to_read = (word_cnt - 1) << 2;
        UART2_readTimeout(uart, b64_buf + 6, bytes_to_read, &bytes_read,
                20000 / Clock_tickPeriod_D);
        if (bytes_read < bytes_to_read)
        {
            // message came too slow, truncated
            _recv_crlf();
            return -4;
        }
    }

    // make sure CRLF terminator is present
    last_byte = word_cnt << 2;
    if (b64_buf[last_byte] != '\r' || b64_buf[last_byte + 1] != '\n')
    {
        // malformed data/sync error
        _recv_crlf();
        return -5;
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
