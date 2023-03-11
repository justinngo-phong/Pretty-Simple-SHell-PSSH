#include <stdio.h>

int main(int argc, char *argv[])
{
	if (argc == 4) {
		printf("The three command line arguments are: %s %s %s\n", argv[1], argv[2], argv[3]);
	} else {
		printf("The program requires exactly three command line arguments.\n");
	}
	return 0;
}
