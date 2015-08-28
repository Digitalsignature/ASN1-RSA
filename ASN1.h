/**********************************************************************
* ASN1 code DER&BER library.
* version: 1.5
*
* July, 5th, 2015
*
* This lib was written by DucThang
* Contact:thangdn.tlu@outlook.com
*
* Every comment would be appreciated.
*
* If you want to use parts of any code of mine:
* let me know and
* use it!
**********************************************************************
privatePEMDE(input)
publicPEMDE(input)
privatePEMEN(input)
publicPEMEN(input)
**********************************************************************/
#ifndef ASN1_H
#define ASN1_H

#include <gmpxx.h>
#include <iostream>
#include <string>
using namespace std;

typedef mpz_class ZZZ;

/*
RSAPrivateKey ::= SEQUENCE {
      version           Version,
      modulus           INTEGER,  -- n
      publicExponent    INTEGER,  -- e
      privateExponent   INTEGER,  -- d
      prime1            INTEGER,  -- p
      prime2            INTEGER,  -- q
      exponent1         INTEGER,  -- d mod (p-1)
      exponent2         INTEGER,  -- d mod (q-1)
      coefficient       INTEGER,  -- (inverse of q) mod p
      otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
*/
struct RSA_Key
{
    ZZZ Version;
    ZZZ modulu_n;
    ZZZ publicExponent_e;
    ZZZ privateExponent_d;
    ZZZ prime_p;
    ZZZ prime_q;
    ZZZ exponent_p;
    ZZZ exponent_q;
    ZZZ coefficient;
};
struct RSA_Public_Key
{
    ZZZ ID;
    ZZZ NULLs;
    ZZZ modulu_n;
    ZZZ publicExponent_e;
};
/*******************ENCODE************************/
string ASNHEX(ZZZ integer)
{
    string hex=integer.get_str(16);
    if(hex.length()%2==0)
        return hex;
    return '0'+hex;
}
string ASNLength(int length,int extra=0)
{
    length=length/2+extra;
    if(length<128)
        return ASNHEX(length);
    else{
        if(length<=255)
            return "81"+ASNHEX(length);
        else{
            return "82"+ASNHEX(length);
        }
    }
}

string ASNIntValue(ZZZ integer, bool nulPrefixed)
{
    string hex=integer.get_str(16);
    if(nulPrefixed)hex="00"+hex;
    if(hex.length()%2!=0)hex='0'+hex;
    return "02"+ASNLength(hex.length())+hex;
}

string privatePEMEN(RSA_Key keys)
{
    string encoded;
    encoded=ASNIntValue(keys.Version,false);
    encoded+=ASNIntValue(keys.modulu_n,true);
    encoded+=ASNIntValue(keys.publicExponent_e,false);
    encoded+=ASNIntValue(keys.privateExponent_d,false);
    encoded+=ASNIntValue(keys.prime_p,true);
    encoded+=ASNIntValue(keys.prime_q,true);
    encoded+=ASNIntValue(keys.exponent_p,true);
    encoded+=ASNIntValue(keys.exponent_q,false);
    encoded+=ASNIntValue(keys.coefficient,false);
    encoded="30"+ASNLength(encoded.length())+encoded;
    return encoded;
}

string publicPEMEN(RSA_Key keys)
{
    string encoded;
    encoded = ASNIntValue(keys.modulu_n,true);
    encoded += ASNIntValue(keys.publicExponent_e,false);
    encoded = "30" + ASNLength(encoded.length()) + encoded;
    encoded = "03" + ASNLength(encoded.length(),1) + "00" + encoded;
    encoded = "300d06092a864886f70D0101010500" + encoded;
    encoded = "30" + ASNLength(encoded.length()) + encoded;
    return encoded;
}
/*******************DECODE************************/

/*
30RSAPrivateKey ::= SEQUENCE {
   02   version           Version,
   02   modulus           INTEGER,  -- n
   02   publicExponent    INTEGER,  -- e
   02   privateExponent   INTEGER,  -- d
   02   prime1            INTEGER,  -- p
   02   prime2            INTEGER,  -- q
   02   exponent1         INTEGER,  -- d mod (p-1)
   02   exponent2         INTEGER,  -- d mod (q-1)
   02   coefficient       INTEGER,  -- (inverse of q) mod p
   02   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
*/
struct HEXA
{

    string code;

    string get(int i)
    {
        string a=code.substr(i*2,2);
        return a;
    }
    int getLength(int i)
    {
        if(get(i)=="81")return 1;
        else if(get(i)=="82")return 2;
        else return 0;
    }
    long getValueLength(int i,int length)
    {
        string a;
        if(length==0)
            a=get(i);
        else
            if(length==1)
                a=get(i+1);
            else
                a=get(i+1)+get(i+2);
        ZZZ cv;cv.set_str(a,16);
        return cv.get_ui();
    }
    string getValueInt(int i,int length)
    {
        string a;
        for(;i<length;i++)
        {
            a+=get(i);
        }
        return a;
    }

}pemcode;
void PEMRead(int &i,vector<string> &keys)
{
        if(pemcode.get(i)=="30")
        {
            i++;
            int length=pemcode.getLength(i);
            //long lengths=pemcode.getValueLength(i,length);
            i=i+length+1;
            PEMRead(i,keys);
        }else
        if(pemcode.get(i)=="02")
        {
            i++;
            int length=pemcode.getLength(i);
            long lengths=pemcode.getValueLength(i,length);
            i=i+length+1;
            keys.push_back(pemcode.getValueInt(i,i+lengths));
            i=i+lengths;
            PEMRead(i,keys);
        }else
        if(pemcode.get(i)=="03")
        {
            i++;
            int length=pemcode.getLength(i);
            long lengths=pemcode.getValueLength(i,length);
            i=i+length+2;

            PEMRead(i,keys);
        }
        if(pemcode.get(i)=="05")
        {
            i++;
            keys.push_back(pemcode.get(i));
            i++;
            PEMRead(i,keys);
        }
        if(pemcode.get(i)=="06")
        {
            i++;
            int length=pemcode.getLength(i);
            long lengths=pemcode.getValueLength(i,length);
            i=i+length+1;
            keys.push_back(pemcode.getValueInt(i,i+lengths));
            i=i+lengths;
            PEMRead(i,keys);
        }
}

RSA_Key privatePEMDE(string code)
{
    pemcode.code=code;
    vector<string> keys;
    int i=0;
    PEMRead(i,keys);

    RSA_Key key;
    key.coefficient.set_str(keys[8],16);
    key.exponent_q.set_str(keys[7],16);
    key.exponent_p.set_str(keys[6],16);
    key.prime_q.set_str(keys[5],16);
    key.prime_p.set_str(keys[4],16);
    key.privateExponent_d.set_str(keys[3],16);
    key.publicExponent_e.set_str(keys[2],16);
    key.modulu_n.set_str(keys[1],16);
    key.Version.set_str(keys[0],16);
    return key;
}

RSA_Public_Key publicPEMDE(string code)
{
    pemcode.code=code;
    vector<string> keys;
    int i=0;
    PEMRead(i,keys);
    RSA_Public_Key key;
    key.publicExponent_e.set_str(keys[3],16);
    key.modulu_n.set_str(keys[2],16);
    key.NULLs.set_str(keys[1],16);
    key.ID.set_str(keys[0],16);
    return key;
}
#endif // ASN1_H
