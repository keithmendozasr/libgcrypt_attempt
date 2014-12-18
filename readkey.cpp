#include <iostream>
#include <fstream>
#include <string>
#include <getopt.h>
#include <arpa/inet.h>

using namespace std;

typedef struct _packet_info {
    bool format;
    char length_type;
    char tag;
} packet_info;

void usage()
{
    cerr<<"Usage: readkey [-f filename|--file=filename]"<<endl;
}

const packet_info getPacketTag(ifstream &inFile)
{
    char header;
    inFile.read(&header, 1);

    packet_info retVal;
    retVal.format = (header & 128);
    retVal.length_type = (header & 3);
    retVal.tag = (header &60) >> 2;

    return move(retVal);
}

const int getBodyLength(const packet_info &p, ifstream &inFile)
{
    int retVal;

    switch(p.length_type)
    {
    case 3:
        throw string("Length is indeterminate type");
    case 0:
        char oneOctet;
        inFile.read(&oneOctet, 1);
        retVal = oneOctet;
        break;
    case 1:
        short twoOctet;
        inFile.read((char *)&twoOctet, sizeof(twoOctet));
        retVal = ntohs(twoOctet);
        break;
    case 2:
        int fourOctet;
        inFile.read((char *)&fourOctet, sizeof(fourOctet));
        retVal = ntohl(fourOctet);
        break;
    }

    return move(retVal);
}

void getPublicKeyPacketInfo(ifstream &inFile)
{
    unsigned char ver;
    unsigned int createTime;
    unsigned char algorithm;

    inFile.read((char *)&ver, sizeof(ver));
    inFile.read((char *)&createTime, sizeof(createTime));
    createTime = ntohl(createTime);

    inFile.read((char *)&algorithm, sizeof(algorithm));

    cout<<"Version: "<<(unsigned int)ver<<endl
        <<"Create time: "<<createTime<<endl
        <<"Algorithm: "<<(unsigned int)algorithm<<endl;
}

void readMPI(ifstream &inFile)
{
    unsigned short len;
    inFile.read((char *)&len, sizeof(len));
    len = ntohs(len);

    cout<<"MPI length: "<<len<<endl;
}

int main(int argc, char **argv)
{
    static struct option opts [] = {
        { "file",   required_argument,  NULL,   'f' },
        { NULL,     0,                  NULL,   0 }
    };

    string fileName;
    int ch;
    while((ch = getopt_long(argc, argv, "f:", opts, NULL)) != -1)
    {
        switch(ch)
        {
        case 'f':
            fileName = string(optarg);
            break;
        default:
            usage();
            return 1;
        }
    };

    int retVal = EXIT_FAILURE;

    if(fileName.length())
    {
        cout<<"Opening file"<<fileName<<endl;
        ifstream inFile;
        inFile.exceptions(ifstream::failbit | ifstream::badbit);
        try
        {
            inFile.open(fileName, ifstream::binary);
            packet_info p = getPacketTag(inFile);
            cout<<"Format: "<<(p.format ? "New" : "Old")<<endl
                <<"Length type: "<<(unsigned short)p.length_type<<endl
                <<"Packet tag: "<<(unsigned short)p.tag<<endl;

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

    return retVal;
}
