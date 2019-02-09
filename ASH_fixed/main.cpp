#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#if _WIN32
unsigned int s32( unsigned int i ) 
{
	return ( (i>>24) | (i<<24) | ((i&0x00FF0000)>>8) | ((i&0x0000FF00)<<8) );
}
unsigned short s16( unsigned short s ) 
{
	return (s>>8) | (s<<8);
}
#else
#include <arpa/inet.h>
unsigned int s32(unsigned int i) { return ntohl(i); }
unsigned int s16(unsigned short s) { return ntohs(s); }
#endif

int main( int argc, char * argv[] )
{

	printf(" ASH v0.1\n by crediar\n");
	printf(" built %s\n", __DATE__ );
	printf(" #wiidev efnet\n\n" );

	if( argc != 2 )
		return 0;
	
	FILE *in = fopen( argv[1], "rb" );

	if( in == NULL )
	{
		printf("Could not open file\n");
		return 0;
	}

	unsigned int magic;

	fread( &magic, sizeof( unsigned int ), 1, in );

	if( (s32(magic)&0xFFFFFF00) != 0x41534800 )
	{
		printf("This is not a valid ASH file\n");
		return 0;
	}

	fseek( in, 0, SEEK_END );

	unsigned int size = ftell( in );

	fseek( in, 0, 0 );

	unsigned int r[32];
	unsigned int count=0;
	unsigned int t;

	r[4] = (unsigned int)(new char [size]);		//in

	//printf("4:%08X\n", r[4]);

	fread( (void*)(r[4]), sizeof( char ), size, in );

	fclose( in );

	r[5] = 0x415348;
	r[6] = 0x415348;

Rvl_decode_ash:

	r[5] = s32(*(unsigned int *)(r[4]+4));
	r[5] = r[5] & 0x00FFFFFF;

	size = r[5];
	printf("Decompressed size: %d\n", size);
	unsigned int o = r[3] = (unsigned int)(new char [size]);	//out
	memset( (void*)(r[3]), 0, size );
	//printf("r[3] :%08X\n", r[3]);

	//printf("\n\n");

	r[24] = 0x10;
	r[28] = s32(*(unsigned int *)(r[4]+8));
	r[25] = 0;
	r[29] = 0;
	r[26] = s32(*(unsigned int *)(r[4]+0xC));
	r[30] = s32(*(unsigned int *)(r[4]+r[28]));
	r[28] = r[28] + 4;
	//r[8]  = 0x8108<<16;
	//HACK, pointer to RAM
	r[8]  = (unsigned int)(new char [0x100000]);
	memset( (void*)(r[8]), 0, 0x100000 );
	//printf("r[8] :%08X\n", r[8]);

	r[8]  = r[8];
	r[9]  = r[8]  + 0x07FE;
	r[10] = r[9]  + 0x07FE;
	r[11] = r[10] + 0x1FFE;
	r[31] = r[11] + 0x1FFE;
	r[23] = 0x200;
	r[22] = 0x200;
	r[27] = 0;

loc_81332124:
	
	if( r[25] != 0x1F )
		goto loc_81332140;

	r[0] = r[26] >> 31;
	r[26]= s32(*(unsigned int *)(r[4] + r[24])); 
	r[25]= 0;
	r[24]= r[24] + 4;
	goto loc_8133214C;

loc_81332140:

	r[0] = r[26] >> 31;
	r[25]= r[25] + 1;
	r[26]= r[26] << 1;

loc_8133214C:

	if( r[0] == 0 )
		goto loc_81332174;

	r[0] = r[23] | 0x8000;
	*(unsigned short *)(r[31]) = s16(r[0]);
	r[0] = r[23] | 0x4000;
	*(unsigned short *)(r[31]+2) = s16(r[0]);

	r[31] = r[31] + 4;
	r[27] = r[27] + 2;
	r[23] = r[23] + 1;
	r[22] = r[22] + 1;

	goto loc_81332124;

loc_81332174:

	r[12] = 9;
	r[21] = r[25] + r[12];
	t = r[21];
	if( r[21] > 0x20 )
		goto loc_813321AC;

	r[21] = (~(r[12] - 0x20))+1;
	r[6]  = r[26] >> r[21];
	if( t == 0x20 )
		goto loc_8133219C;

	r[26] = r[26] << r[12];
	r[25] = r[25] +  r[12];
	goto loc_813321D0;

loc_8133219C:

	r[26]= s32(*(unsigned int *)(r[4] + r[24]));
	r[25]= 0;
	r[24]= r[24] + 4;
	goto loc_813321D0;

loc_813321AC:

	r[0] = (~(r[12] - 0x20))+1;
	r[6] = r[26] >> r[0];
	r[26]= s32(*(unsigned int *)(r[4] + r[24]));
	r[0] = (~(r[21] - 0x40))+1;
	r[24]= r[24] + 4;
	r[0] = r[26] >> r[0];
	r[6] = r[6] | r[0];
	r[25] = r[21] - 0x20;
	r[26] = r[26] << r[25];

loc_813321D0:

	r[12]= s16(*(unsigned short *)(r[31] - 2));
		r[31] -= 2;
	r[27]= r[27] - 1;
	r[0] = r[12] & 0x8000;
	r[12]= (r[12] & 0x1FFF) << 1;
	if( r[0] == 0 )
		goto loc_813321F8;

	*(unsigned short *)(r[9]+r[12]) = s16(r[6]);
	r[6] = (r[12] & 0x3FFF)>>1;							//	extrwi  %r6, %r12, 14,17
	if( r[27] != 0 )
		goto loc_813321D0;

	goto loc_81332204;

loc_813321F8:

	*(unsigned short *)(r[8]+r[12]) = s16(r[6]);
	r[23] = r[22];
	goto loc_81332124;

loc_81332204:

	r[23] = 0x800;
	r[22] = 0x800;

loc_8133220C:

	if( r[29] != 0x1F )
		goto loc_81332228;

	r[0] = r[30] >> 31;
	r[30]= s32(*(unsigned int *)(r[4] + r[28]));
	r[29]= 0;
	r[28]= r[28] + 4;
	goto loc_81332234;

loc_81332228:

	r[0] = r[30] >> 31;
	r[29]= r[29] +  1;
	r[30]= r[30] << 1;

loc_81332234:

	if( r[0] == 0 )
		goto loc_8133225C;

	r[0] = r[23] | 0x8000;
	*(unsigned short *)(r[31]) = s16(r[0]);
	r[0] = r[23] | 0x4000;
	*(unsigned short *)(r[31]+2) = s16(r[0]);

	r[31] = r[31] + 4;
	r[27] = r[27] + 2;
	r[23] = r[23] + 1;
	r[22] = r[22] + 1;

	goto loc_8133220C;

loc_8133225C:

	r[12] = 0xB;
	r[21] = r[29] + r[12];
	t = r[21];
	if( r[21] > 0x20 )
		goto loc_81332294;

	r[21] = (~(r[12] - 0x20))+1;
	r[7]  = r[30] >> r[21];
	if( t == 0x20 )
		goto loc_81332284;

	r[30] = r[30] << r[12];
	r[29] = r[29] +  r[12];
	goto loc_813322B8;

loc_81332284:

	r[30]= s32(*(unsigned int *)(r[4] + r[28]));
	r[29]= 0;
	r[28]= r[28] + 4;
	goto loc_813322B8;

loc_81332294:

	r[0] = (~(r[12] - 0x20))+1;
	r[7] = r[30] >> r[0];
	r[30]= s32(*(unsigned int *)(r[4] + r[28]));
	r[0] = (~(r[21] - 0x40))+1;
	r[28]= r[28] + 4;
	r[0] = r[30] >> r[0];
	r[7] = r[7] | r[0];
	r[29]= r[21] - 0x20;
	r[30]= r[30] << r[29];

loc_813322B8:

	r[12]= s16(*(unsigned short *)(r[31] - 2));
		r[31] -= 2;
	r[27]= r[27] - 1;
	r[0] = r[12] & 0x8000;
	r[12]= (r[12] & 0x1FFF) << 1;
	if( r[0] == 0 )
		goto loc_813322E0;

	*(unsigned short *)(r[11]+r[12]) = s16(r[7]);
	r[7] = (r[12] & 0x3FFF)>>1;							// extrwi  %r7, %r12, 14,17
	if( r[27] != 0 )
		goto loc_813322B8;

	goto loc_813322EC;

loc_813322E0:
	
	*(unsigned short *)(r[10]+r[12]) = s16(r[7]);
	r[23] = r[22];
	goto loc_8133220C;

loc_813322EC:

	r[0] = r[5];

loc_813322F0:

	r[12]= r[6];

loc_813322F4:

	if( r[12] < 0x200 )
		goto loc_8133233C;

	if( r[25] != 0x1F )
		goto loc_81332318;

	r[31] = r[26] >> 31;
	r[26] = s32(*(unsigned int *)(r[4] + r[24]));
	r[24] = r[24] + 4;
	r[25] = 0;
	goto loc_81332324;

loc_81332318:

	r[31] = r[26] >> 31;
	r[25] = r[25] +  1;
	r[26] = r[26] << 1;

loc_81332324:

	r[27] = r[12] << 1;
	if( r[31] != 0 )
		goto loc_81332334;

	r[12] = s16(*(unsigned short *)(r[8] + r[27]));
	goto loc_813322F4;

loc_81332334:

	r[12] = s16(*(unsigned short *)(r[9] + r[27]));
	goto loc_813322F4;

loc_8133233C:

	if( r[12] >= 0x100 )
		goto loc_8133235C;

	*(unsigned char *)(r[3]) = r[12];
	r[3] = r[3] + 1;
	r[5] = r[5] - 1;
	if( r[5] != 0 )
		goto loc_813322F0;

	goto loc_81332434;

loc_8133235C:

	r[23] = r[7];

loc_81332360:

	if( r[23] < 0x800 )
		goto loc_813323A8;

	if( r[29] != 0x1F )
		goto loc_81332384;

	r[31] = r[30] >> 31;
	r[30] = s32(*(unsigned int *)(r[4] + r[28]));
	r[28] = r[28] + 4;
	r[29] = 0;
	goto loc_81332390;

loc_81332384:

	r[31] = r[30] >> 31;
	r[29] = r[29] +  1;
	r[30] = r[30] << 1;

loc_81332390:

	r[27] = r[23] << 1;
	if( r[31] != 0 )
		goto loc_813323A0;

	r[23] = s16(*(unsigned short *)(r[10] + r[27]));
	goto loc_81332360;

loc_813323A0:

	r[23] = s16(*(unsigned short *)(r[11] + r[27]));
	goto loc_81332360;

loc_813323A8:

	r[12] = r[12] - 0xFD;
	r[23] = ~r[23] + r[3] + 1;
	r[5]  = ~r[12] + r[5] + 1;
	r[31] = r[12] >> 3;

	if( r[31] == 0 )
		goto loc_81332414;

	count = r[31];

loc_813323C0:

	r[31] = *(unsigned char *)(r[23] - 1);
	*(unsigned char *)(r[3]) = r[31];

	r[31] = *(unsigned char *)(r[23]);
	*(unsigned char *)(r[3]+1) = r[31];

	r[31] = *(unsigned char *)(r[23] + 1);
	*(unsigned char *)(r[3]+2) = r[31];

	r[31] = *(unsigned char *)(r[23] + 2);
	*(unsigned char *)(r[3]+3) = r[31];

	r[31] = *(unsigned char *)(r[23] + 3);
	*(unsigned char *)(r[3]+4) = r[31];

	r[31] = *(unsigned char *)(r[23] + 4);
	*(unsigned char *)(r[3]+5) = r[31];

	r[31] = *(unsigned char *)(r[23] + 5);
	*(unsigned char *)(r[3]+6) = r[31];

	r[31] = *(unsigned char *)(r[23] + 6);
	*(unsigned char *)(r[3]+7) = r[31];

	r[23] = r[23] + 8;
	r[3]  = r[3]  + 8;

	if( --count )
		goto loc_813323C0;

	r[12] = r[12] & 7;
	if( r[12] == 0 )
		goto loc_8133242C;

loc_81332414:

	count = r[12];

loc_81332418:

	r[31] = *(unsigned char *)(r[23] - 1);
	r[23] = r[23] + 1;
	*(unsigned char *)(r[3]) = r[31];
	r[3]  = r[3] + 1;

	if( --count )
		goto loc_81332418;

loc_8133242C:

	if( r[5] != 0 )
		goto loc_813322F0;

loc_81332434:

	r[3] = r[0];

	//for( int i=0; i < 32; ++i )
	//	printf("%d:%08X\n", i, r[i]);

	printf("Decompressed %d bytes\n", r[3]);

	//printf("24:%08X\n", r[24]);
	//printf("28:%08X\n", r[28]);
	//printf("31:%08X\n", r[31]);
	//printf("31:%08X\n", r[31]);
	//printf("YY:%08X\n", r[27]+r[0]);

	char * str[1024];

	sprintf(( char *)str, "%s.arc", argv[1] );

	FILE *out = fopen((const char *)str, "wb" );

	if( out == NULL )
	{
		printf("Could not create/write file\n");
		return 0;
	}

	printf("Wrote:%d\n", fwrite( (void*)(o), sizeof( char ), r[3], out ) );

	fclose( out );

	
	return 1;
}