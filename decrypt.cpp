#include <iostream>
#include <fstream>
#include <string>
#include <getopt.h>
#include <arpa/inet.h>
#include <cstdint>
#include <ctime>
#include <array>
#include <sstream>

#define GCRPYT_NO_DEPRECATED
#include <gcrypt.h>

using namespace std;

typedef struct _packet_info {
    bool format;
    uint8_t length_type;
    uint8_t tag;
} packet_info;

void usage()
{
    cerr<<"Usage: decrypt [-f filename|--file=filename] [-k|--key=privatekey]"<<endl;
}

inline static void printErrInfo(const string &msg, gcry_error_t err)
{
    cerr<<msg<<" Source: \""<<gcry_strsource(err)<<"\" Error: \""<<gcry_strerror(err)<<"\""<<endl;
}

bool initLibGcrypt()
{
    const char gcryptVersion[] = "1.6.2";
    if(!gcry_check_version(gcryptVersion))
    {
        cerr<<"Application expects libgcrypt v."<<gcryptVersion<<" or greater"<<endl;
        return false;
    }

    bool retVal = false;

    gcry_error_t err;
    if((err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN)))
        printErrInfo("Failed to suspend secmem warnings", err);
    else if((err = gcry_control(GCRYCTL_INIT_SECMEM, 1, 0)))
        printErrInfo("Failed to allocate secure memory", err);
    else if((err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0)))
        printErrInfo("Failed to flag initalization complete", err);
    else
        retVal = true;

    return retVal;
}

const packet_info getPacketTag(const uint8_t data)
{
    packet_info retVal;
    retVal.format = (data & 64);
    if(retVal.format)
    {
        retVal.tag = (data & 63);
    }
    else
    {
        retVal.length_type = (data & 3);
        retVal.tag = (data &60) >> 2;
    }

    return move(retVal);
}

const packet_info getPacketTag(ifstream &inFile)
{
    uint8_t header;
    inFile>>header;

    return move(getPacketTag(header));
}

void printPacketInfo(const packet_info &p)
{
    cout<<"Format: "<<(p.format ? "New" : "Old")<<endl;
    if(!p.format)
        cout<<"Length type: "<<(unsigned short)p.length_type<<endl;
    cout<<"Packet tag: "<<(unsigned short)p.tag<<endl;
}

const size_t getBodyLength(ifstream &inFile, const packet_info &p)
{
    size_t retVal;

    switch(p.length_type)
    {
    case 3:
        throw out_of_range("Length is indeterminate type");
    case 0:
        cout<<"Length is 1 octet"<<endl;
        uint8_t oneOctet;
        inFile >> oneOctet;
        retVal = oneOctet;
        break;
    case 1:
        cout<<"Length is 2 octets"<<endl;
        uint16_t twoOctet;
        inFile.read(reinterpret_cast<char *>(&twoOctet), sizeof(twoOctet));
        retVal = ntohs(twoOctet);
        break;
    case 2:
        cout<<"Length is 4 octets"<<endl;
        uint32_t fourOctet;
        inFile >> fourOctet;
        retVal = ntohl(fourOctet);
        break;
    }

    return retVal;
}

gcry_mpi_t readMPI(const char* buf, const size_t &bufLen, size_t &nscanned)
{
    gcry_mpi_t retVal = gcry_mpi_snew(2048);
    gcry_error_t err = gcry_mpi_scan(&retVal, GCRYMPI_FMT_PGP, buf, bufLen, &nscanned);
    
    if(err)
    {
        throw string("Error encountered scanning mpi. Source: ") + string(gcry_strsource(err)) + string(" Cause: ") + string(gcry_strerror(err));
    }

    unsigned char *printBuf;
    size_t printBufSize;
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &printBuf, &printBufSize, retVal);
    printBuf[printBufSize-1] = '\0';
    cout<<"retVal: "<<printBuf<<endl
        <<"Value of nscanned: "<<nscanned<<endl;
    
    return retVal;
}

gcry_sexp_t getPublicKeySexp(weak_ptr<char> data, size_t &nextPos, size_t &dataSize)
{
    uint8_t ver;
    uint32_t createTime;
    uint8_t algorithm;
    gcry_sexp_t sexp;

    if(auto ptr = data.lock())
    {
        cout<<__PRETTY_FUNCTION__<<" Starting dataSize: "<<dataSize<<endl;

        const char * dataPtr = ptr.get();

        ver = dataPtr[nextPos];
        dataSize--;
        nextPos++;

        memmove(&createTime, &(dataPtr[nextPos]), sizeof(uint32_t));
        nextPos += sizeof(uint32_t);
        dataSize -= sizeof(uint32_t);
        createTime = ntohl(createTime);

        algorithm = dataPtr[nextPos];
        nextPos++;
        dataSize--;

        cout<<"Version: "<<ver<<endl
            <<"Create time: ";
            {
                char *tmp = ctime(reinterpret_cast<const time_t *>(&createTime));
                if(tmp)
                    cout<<tmp;
                else
                {
                    int err = errno;
                    cout<<createTime<<" (Warning: Error converting time. Cause: "<<strerror(err)<<")";
                }
                cout<<endl;
            }
        cout<<"Algorithm: "<<(unsigned short)algorithm<<endl;

        //Get RSA modulus
        size_t nscanned;
        gcry_mpi_t modulus = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize-= nscanned;
        nextPos += nscanned;

        if(!dataSize)
            throw string("Ran out of room for exponent portion of public key");

        gcry_mpi_t exponent = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize -= nscanned;
        nextPos += nscanned;
        
        size_t errOff;
        gcry_error_t gcry_err = gcry_sexp_build(&sexp, &errOff, "(n%m)(e%m)", modulus, exponent);
        if(gcry_err)
        {
            ostringstream errMsg;
            errMsg << "Error encoutered building s-expression for public key. Source: "<<gcry_strsource(gcry_err)
                <<" Error: "<< gcry_strerror(gcry_err)
                <<" Format offset: " << errOff;
            throw errMsg.str();
        }

        cout<<"Ending dataSize: "<<dataSize<<endl;
    }
    else
        throw invalid_argument("Expired shared_ptr parameter provided");

    return move(sexp);
}

void parseStringToKey(const char *data, size_t &nextPos, size_t &dataSize)
{
    if(data)
    {
        cout<<__PRETTY_FUNCTION__<<" Starting value of dataSize: "<<dataSize<<endl;

        char s2k = data[nextPos];
        cout<<"Value of s2k: "<<(int)s2k<<endl;

        nextPos++;
        dataSize--;

        if(s2k)
            throw out_of_range("String-to-key other than 0 is not supported");
    }
    else
        throw invalid_argument("NULL pointer provided to \"data\" parameter");
}

const uint16_t parsePrivateKeyCksum(const char *data, size_t &nextPos, size_t &dataSize)
{
    uint16_t cksum;
    if(data)
    {
        memmove(&cksum, &data[nextPos], sizeof(cksum));
        cksum = ntohs(cksum);
        cout<<"Value of cksum: "<<cksum<<endl;

        dataSize-= sizeof(cksum);
        nextPos += sizeof(cksum);
        cout<<__PRETTY_FUNCTION__<<" Ending value of dataSize: "<<dataSize<<endl;
    }
    else
        throw invalid_argument("Expired share_ptr provided");

    return cksum;
}

void parsePrivateKey(const string &fileName)
{
    ifstream inFile;
    inFile.exceptions(ifstream::failbit | ifstream::badbit);
    inFile.open(fileName, ios::binary);

    const packet_info info = getPacketTag(inFile);
    printPacketInfo(info);
    if(info.tag != 5)
        throw move(string(fileName + " is not a private key file"));

    if(info.format)
        throw move(string("Unable to handle new format packet at this time"));
    cout<<"Parse out public key part"<<endl;
    size_t dataLen = getBodyLength(inFile, info);
    cout<<"Key length: "<<dataLen<<endl;

    shared_ptr<char> body(reinterpret_cast<char *>(gcry_calloc_secure(dataLen, sizeof(char))), [](void *p){ gcry_free(p); } );
    try
    {
        inFile.read(body.get(), dataLen);
        size_t nextPos = 0;
        gcry_sexp_t pubKeySexp =  getPublicKeySexp(body, nextPos, dataLen);
        cout<<"Public key built"<<endl;

        //size_t nscanned;
        char *dataPtr = body.get();
        dataPtr += dataLen;

        if(nextPos > dataLen)
            throw string("Ran out of data for string-to-key convention");

        parseStringToKey(dataPtr, nextPos, dataLen);
        nextPos = dataLen;

        const uint16_t privKeyCksum = parsePrivateKeyCksum(dataPtr, nextPos, dataLen);
        cout<<"Value of private key checksum: "<<privKeyCksum<<endl;

        /*gcry_mpi_t d_mpi = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize -= nscanned;
        nextPos += nscanned;
        cout<<"d complete"<<endl;

        if(nextPos > dataLen)
            throw string("Ran out of data for p-mpi");
        gcry_mpi_t p_mpi = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize -= nscanned;
        nextPos += nscanned;
        cout<<"p complete"<<endl;

        if(nextPos > dataLen)
            throw string("Ran out of data for q-mpi");
        gcry_mpi_t q_mpi = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize -= nscanned;
        nextPos += nscanned;
        cout<<"q complete"<<endl;

        if(nextPos > dataLen)
            throw string("Ran out of data for u-mpi");
        gcry_mpi_t u_mpi = readMPI(&dataPtr[nextPos], dataSize, nscanned);
        dataSize -= nscanned;
        nextPos += nscanned;
        cout<<"u complete"<<endl;

        gcry_sexp_t privKeySexp;
        size_t errOff;
        gcry_error_t gcry_err = gcry_sexp_build(&privKeySexp, &errOff, "(private-key(rsa(%S(d%m)(p%m)(q%m)(u%m))))", pubKeySexp, d_mpi, p_mpi, q_mpi, u_mpi);
        if(gcry_err)
        {
            ostringstream errMsg;
            errMsg << "Error encoutered building s-expression for private key. Source: "<<gcry_strsource(gcry_err)
                <<" Error: "<< gcry_strerror(gcry_err)
                <<" Format offset: " << errOff;
            throw errMsg.str();
        }
        cout<<"Private key built"<<endl;
        gcry_sexp_dump(privKeySexp);*/

        gcry_sexp_release(pubKeySexp);
        //gcry_sexp_release(privKeySexp);
    }
    catch(const ifstream::failure &e)
    {
        if(inFile.eof())
            throw "Unexpected eof encountered";
        else
            throw e.what();
    }
}

int main(int argc, char **argv)
{
    static struct option opts [] = {
        { "file",   required_argument,  NULL,   'f' },
        { "key",    required_argument,  NULL,   'k' },
        { NULL,     0,                  NULL,   0 }
    };

    string fileName;
    string keyFile;
    int ch;
    while((ch = getopt_long(argc, argv, "f:k:", opts, NULL)) != -1)
    {
        switch(ch)
        {
        case 'f':
            fileName = string(optarg);
            break;
        case 'k':
            keyFile = string(optarg);
            break;
        default:
            usage();
            return EXIT_FAILURE;
        }
    };

    if(!fileName.length() || !keyFile.length())
    {
        usage();
        return EXIT_FAILURE;
    }

    if(!initLibGcrypt())
        return EXIT_FAILURE;

    int retVal = EXIT_FAILURE;

    try
    {
        parsePrivateKey(keyFile);
    }
    catch(const string &e)
    {
        cerr<<"Error \""<<e<<"\" Terminating program"<<endl;
    }
    /*catch(const ios::failure &e)
    {
        cerr<<"Error encountered reading file. Cause: "<<e.what()<<endl;
    }*/
    
    /*
    if(fileName.length())
    {
        cout<<"Opening file"<<fileName<<endl;
        ifstream inFile;
        inFile.exceptions(ifstream::failbit | ifstream::badbit);
        try
        {
            inFile.open(fileName, ifstream::binary);
            packet_info p = getPacketTag(inFile);

            int length = getBodyLength(p, inFile);
            cout<<"Body length: "<<length<<endl;

            getPublicKeyPacketInfo(inFile);
            readMPI(inFile);
            retVal = EXIT_SUCCESS;
        }
        catch(ifstream::failure e)
        {
            cerr<<"Error encounted processing. Cause: "<<e.what()<<endl;
        }
    }
    else
        usage();
    */

    return retVal;
}
