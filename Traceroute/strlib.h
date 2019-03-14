#ifndef _STRLIB_H
#define _STRLIB_H

//вывод сообщени€ дл€ пользовател€, ввод строки пользователем
//msg - сообщение пользователю, Length - максимальна€ длина строки
char *str_input(const char msg[], int Length);

#define LeftSide 0
#define RightSide 1
//возвращает часть строки str до/после индекса ind
//side - отвечает за направление от ind 
//LeftSide - вс€ строка слева от ind 
//RightSide - вс€ строка справа от ind
char *str_part(char *str, const int ind, const int side);

//удаление numb элементов из строки str с позиции pos 
void str_delete(char **str, const int pos, const unsigned int numb);

//удаление всех пробелов из строки str
void str_delete_spaсe(char *str);

#endif // !_STRLIB_H

