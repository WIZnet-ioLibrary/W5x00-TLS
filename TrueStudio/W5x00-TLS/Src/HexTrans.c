/*
 * HexTrans.c
 *
 *  Created on: 2019. 3. 28.
 *      Author: Teddy
 */
#include "HexTrans.h"
#include "main.h"
#include <stdio.h>

//char to hex function
char char2hex(unsigned char data, unsigned char *r_data)
{
	unsigned char temp_data = 0;
	int i;
	for(i = 0; i < 2; i++)
	{
		temp_data = (data >> (i*4)) & 0x0F;
		if(temp_data < 0x0a)
		{
			r_data[i] = '0' + temp_data;
		}
		else
		{
			r_data[i] = 'A' + temp_data - 0x0a;
		}
	}
	if((r_data[0] < '0')||(r_data[1] < '0'))
		return 1;
	return 0;

}

//hex debug print function
char string_print_Hex(unsigned char *buf, unsigned int len)
{
	unsigned int temp_len = 0;
	unsigned char temp_data[2], temp_buf;
	for(temp_len = 0; temp_len < len; temp_len++)
	{
		temp_buf = buf[temp_len];
		if(char2hex(temp_buf, temp_data) != 0)
		{
			printf("trans hex faill len[%d] \r\n", temp_len);
			continue;
		}
		printf("%c%c ",temp_data[1],temp_data[0]);
		if((((temp_len + 1) % 16) == 0)&&(temp_len != 0))
			printf("\r\n");
	}
	printf("\r\n");
	return 0;
}
