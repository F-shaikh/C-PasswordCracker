/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the written permission of the copyright holder.
 */

// Faisal Shaikh
// 1/24/19
// CMPS 122
// Professor Arden

#define _GNU_SOURCE
#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/types.h>
#include <fcntl.h>

char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd)
{
    char crackPassword [13];
    char salt[2];
    strncpy(salt,username,2);
    char* encryption;

    for(int i = 0; i < 62; i++)
    {
        for (int j = 0; j < 62; j++)
        {
            for (int k = 0; k < 62; k++)
            {
                for (int l = 0; l < 62; l++)
                {
                    memset(crackPassword,0,13);
                    crackPassword[0] = set[i];
                    crackPassword[1] = set[j];
                    crackPassword[2] = set[k];
                    crackPassword[3] = set[l];

                    encryption = crypt(crackPassword,salt);
                    if (strcmp(cryptPasswd,encryption) == 0)
                    {
                        strncpy(passwd,crackPassword,strlen(crackPassword));
                    }
                }
            }
        }
    }
}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds)
{
    int counter = 0;
    char lines[1000];
    char multipleUsername [100];
    char multipleCrackPassword[13];
    FILE *fileName = fopen(fname, "r");
    
    while(fgets(lines,1000,fileName) != NULL)
    {
        int i = 0; // lines buffer location
        int j = 0; // multipleUsername buffer location
        int k = 0; // multipleCrackPassword buffer location
        int colonCount = 0;
        while(lines[i] != EOF)
        {
            if(lines[i] == ':')
            {
                i++;
                colonCount++;
            }
            else if(colonCount == 0)
            {
                multipleUsername[j] = lines[i];
                i++;
                j++;
            }
            else if(colonCount == 1)
            {
                multipleUsername[j] = 0;
                multipleCrackPassword[k] = lines[i];
                i++;
                k++;
            }
            else if(colonCount == 2)
            {
                multipleCrackPassword[k] = 0;
                crackSingle(multipleUsername,multipleCrackPassword,pwlen,passwds[counter++]);
                while(lines[i] != '\n')
                {
                    i++;
                }
                colonCount = 0;
            }
        }
    }
    fclose(fileName);
}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds)
{
    crackMultiple(fname, pwlen,passwds);
} 

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD withoiut using more than MAXCPU
 * percent of any processor.
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu)
{ 
    crackSingle(username,cryptPasswd,pwlen,passwd);
}
