/* 
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without 
 * the written permission of the copyright holder.
 */

void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd);
void crackMultiple(char *fname, int pwlen, char **passwds);
void crackSpeedy(char *fname, int pwlen, char **passwds);
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu);
