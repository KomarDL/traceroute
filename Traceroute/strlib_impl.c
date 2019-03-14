#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "strlib.h"

char *str_input(const char msg[], int Length)
{
	int n = Length;
	char *Res = (char*)calloc(n, sizeof(char));
	printf_s(msg);
	gets_s(Res, n);
	Res = realloc(Res, (strlen(Res) + 1) * sizeof(char));
	return Res;
}

char *str_part(char *str, const int ind, const int side)
{
	if (str != NULL)
	{
		char *Res = (char*)calloc(strlen(str) + 1, sizeof(char));
		int j = 0;
		if (side)
		{
			for (unsigned int i = ind + 1; i < strlen(str); i++)
				Res[j++] = str[i];
		}
		else
		{
			for (int i = 0; i < ind; i++)
				Res[j++] = str[i];
		}
		if (strlen(Res) != 0)
			Res = realloc(Res, (strlen(Res) + 1));
		else
			Res = realloc(Res, strlen(Res));
		return Res;
	}
	else
		return NULL;
}

void str_delete(char **str, const int pos, const unsigned int numb)
{
	if (str != NULL)
	{
		if ((*str) != NULL)
		{
			for (unsigned int i = abs(pos); i + numb <= strlen((*str)); i++)
			{
				(*str)[i] = (*str)[i + numb];
			}
			if (strlen(*str) != 0)
				(*str) = realloc((*str), (strlen((*str)) + 1));
			else
				(*str) = realloc((*str), strlen(*str));
		}
	}
}

void str_delete_spañe(char *str)
{
	if (str != NULL)
	{
		int unsigned i = 0;
		while (i <= strlen(str))
		{
			if (str[i] == ' ')
				str_delete(&str, i, 1);
			else
				i++;
		}
		if (strlen(str) != 0)
			str = realloc(str, (strlen(str) + 1));
		else
			str = realloc(str, strlen(str));
	}
}