// pch.h: esse é um arquivo de cabeçalho pré-compilado.
// Os arquivos listados a seguir são compilados somente uma vez, melhorando o desempenho dos builds futuros.
// Isso também afeta o desempenho do IntelliSense, incluindo a conclusão de código e muitos recursos de navegação de código.
// No entanto, os arquivos listados aqui serão TODOS recompilados se qualquer um deles for atualizado entre builds.
// Não adicione aqui arquivos que você atualizará com frequência, pois isso anula a vantagem de desempenho.

#ifndef PCH_H
#define PCH_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS true

// adicione os cabeçalhos que você deseja pré-compilar aqui
#include "framework.h"
#include "Config.h"

#include <stdio.h>
#include <cstdio>

#include <iomanip>
#include <iostream>

#include <string>
using std::string;

// load WinSock Lib
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

#endif //PCH_H
