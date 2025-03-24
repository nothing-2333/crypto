#pragma once

#include <stdint.h>

/**
 * \brief          SM3上下文结构体
 */
typedef struct
{
    uint32_t total[2];     /*!< 已处理的字节总数（64位计数器，分高低两部分存储） */
    uint32_t state[8];     /*!< 中间摘要状态（8个32位变量，存储哈希计算的中间结果） */
    uint8_t buffer[64];   /*!< 当前处理的数据分组块（SM3算法按64字节分块处理输入数据） */
} sm3_context;

/**
 * \brief          初始化SM3上下文
 *
 * \param ctx      需要初始化的上下文
 */
void sm3_starts(sm3_context *ctx);

/**
 * \brief          处理输入数据块
 *
 * \param ctx      SM3上下文
 * \param input    输入数据缓冲区
 * \param ilen     输入数据的长度
 */
void sm3_update(sm3_context *ctx, uint8_t *input, int ilen);

/**
 * \brief          完成 SM3 计算并生成最终摘要
 *
 * \param ctx      SM3 上下文
 * \param output   输出的摘要结果（32字节）
 */
void sm3_finish(sm3_context *ctx, uint8_t output[32]);

/**
 * \brief          计算输入数据的 SM3 摘要
 *
 * \param input    输入数据缓冲区
 * \param ilen     输入数据的长度
 * \param output   输出的摘要结果（32字节）
 */
void sm3(uint8_t *input, int ilen, uint8_t output[32]);
