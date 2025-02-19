#include <stdlib.h>
#include <stdio.h>

/* PC1 maps input bytes to C and D registers  */

static int PC1_C[] = {      
                57,49,41,33,25,17, 9,
                1,58,50,42,34,26,18,
                10, 2,59,51,43,35,27,
                19,11, 3,60,52,44,36
};

static int PC1_D[] = {      
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14, 6,61,53,45,37,29,
                21,13, 5,28,20,12, 4
};

/* key shift schedule */

static int shifts[] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };


/* PC2  selects CD bits to generate selected key */

static int PC2_C[] = {
    14,17,11,24, 1, 5,
     3,28,15, 6,21,10,
    23,19,12, 4,26, 8,
    16, 7,27,20,13, 2
};

static int PC2_D[] = {
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

/* The C and D arrays used to calculate the key schedule */

static int C[28];
static int D[28];

static int input[16][64];   /* Input key bits used in each KS */
static int corre[16][16];   /* correlation between keys */
static int c[28];
static int d[28];
static int cd_bits[16][48];

/* The scheduled keys, indexed by round */

static int KS[16][48];

/* Fill the key schedule */

void key_sched() {

register int index, round, shift_sched;
int temp;
int     tempcd;

/* Load C and D with input block bit values */

    for(index = 0; index < 28; index++) {
    C[index] = PC1_C[index];
    c[index] = index+1;
    D[index] = PC1_D[index];
    d[index] = index+28+1;
    }

/* Rotate C and D according to key schedule apply PC2 */

    for( round = 0; round < 16; round++) {

    /* first rotate */

    for(shift_sched=0;shift_sched < shifts[round];shift_sched++) {
        temp = C[0];
        tempcd = c[0];
        for(index = 0; index < 28-1; index++) {
        C[index] = C[index+1];
        c[index] = c[index+1];
        }
        C[27] = temp;
        c[27] = tempcd;
        temp = D[0];
        tempcd = d[0];
        for(index = 0; index < 28-1; index++) {
        D[index] = D[index+1];
        d[index] = d[index+1];
        }
        D[27] = temp;
        d[27] = tempcd;
    }

    /* Apply PC2 and store in selected key */

    for(index = 0; index < 24; index++) {
        KS[round][index] = C[PC2_C[index]-1];
        cd_bits[round][index] = c[PC2_C[index]-1];;
        KS[round][index+24] = D[PC2_D[index]-28-1];
        cd_bits[round][index+24] = d[PC2_D[index]-28-1];
    }
    }
}

void key_input() {
int index;
int round;

     for ( round = 0; round < 16; round++ )
         for (index = 0; index < 48; index++) {
             input[round][KS[round][index]] = 1; /* mark those used */
         }
}

void key_core() {
int key1,key2;
int keybit;
    for (key1 = 0; key1 < 16; key1++)  
        for (key2 = 0; key2 < 16; key2++) {
            corre[key1][key2] = 0;
        for (keybit = 0; keybit < 64; keybit++) 
            if (input[key1][keybit] & input[key2][keybit])
                corre[key1][key2]+= 1;
        }
    printf("\n\nKS  ");
    for (key1 = 0; key1 < 16; key1++)
        printf("%2d ",key1+1);
    printf("\n\n");

    for (key1 = 0; key1 < 16; key1++) {
        printf("%2d  ",key1+1);
        for (key2 = 0; key2 < 16; key2++) {
            if (corre[key1][key2] == 48)
                printf("   ");
            else
                printf("%2d ",corre[key1][key2]);
        }
        printf("\n");
    }
    printf("\n");
}

#define MAX_STR 2048
int main (argc,argv) 
int argc;
char *argv[];
{
int round;
int keybit;
extern int getopt();
extern char *optarg;
extern int optind, opterr;
char *ofile;
int input_block = 0;
int input_bit = 0;
int input_corre = 0;
int cd_bit = 0;
int i;

    while ( (i=getopt(argc,argv,"cibso:")) != -1 )  {
        switch (i) {
        case 'c':
            input_corre = 1;
    break;
        case 'i':
            input_bit = 1;
    break;
        case 'b':
            input_block = 1;
    break;
    case 's':
        cd_bit = 1;
    break;
        case 'o':
            ofile = optarg;
            if(freopen(optarg,"w",stdout) == NULL) {
                fprintf(stderr,"ERROR:%s, can't open %s for output\n",
                        argv[0],optarg);
                exit(-1);
            }
        break;
        case '?':
            fprintf(stderr,"usage: %s [-i][-c][-b][-o outfile] \n",argv[0]);
            fprintf(stderr,"\t-i shows which input block bits are used in each round\n");
            fprintf(stderr,"\t-c shows number of key bits in common between rounds\n");
            fprintf(stderr,"\t-b outputs key tables shown as input block bits\n"); 
            fprintf(stderr,"\t-s outputs key tables shown as CD reg bits\n"); 
            exit (-1);
        break;
        }
    }

    key_sched();

    if (cd_bit) {
        printf("\nTable of CD Reg selected key bits\n\n");
        printf("\n  Bit ");
        for ( keybit = 0; keybit < 24 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKS\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 0; keybit < 24; keybit++) 
                printf("%2d ",cd_bits[round][keybit]);
        printf("\n");
        }

        printf("\n  Bit ");
        for ( keybit = 24; keybit < 48 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKS\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 24; keybit < 48; keybit++) 
                printf("%2d ",cd_bits[round][keybit]);
            printf("\n");
        }
        printf("\n%c",'\014');
    }


    if (input_block) {
        printf("\nTable of Input Block selected key bits\n\n");
        printf("\n  Bit ");
        for ( keybit = 0; keybit < 48 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKS\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 0; keybit < 48; keybit++) 
                printf("%2d ",KS[round][keybit]);
        printf("\n");
        }

        // printf("\n  Bit ");
        // for ( keybit = 24; keybit < 48 ; keybit++)
        //     printf("%2d ",keybit+1);

        // printf("\nKS\n");

        // for ( round = 0; round < 16; round++) {
        //     printf("  %2d  ",round+1);
        //     for (keybit = 24; keybit < 48; keybit++) 
        //         printf("%2d ",KS[round][keybit]);
        //     printf("\n");
        // }
        // printf("\n%c",'\014');
    }

    key_input();

    if (input_bit) {
        printf("\n  Bit ");
        for ( keybit = 0; keybit < 24 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKey\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 0; keybit < 24; keybit++) 
                printf(" %c ",(input[round][keybit])?'X':'.');
        printf("\n");
        }

        printf("\n  Bit ");
        for ( keybit = 24; keybit < 48 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKey\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 24; keybit < 48; keybit++) 
                printf(" %c ",(input[round][keybit])?'X':'.');
            printf("\n");
        }
        printf("\n");
        printf("\n  Bit ");
        for ( keybit = 48; keybit < 64 ; keybit++)
            printf("%2d ",keybit+1);

        printf("\nKey\n");

        for ( round = 0; round < 16; round++) {
            printf("  %2d  ",round+1);
            for (keybit = 48; keybit < 64; keybit++) 
                printf(" %c ",(input[round][keybit])?'X':'.');
        printf("\n");
        }
    }    
    if (input_corre) 
        key_core();
    exit (0);
}
