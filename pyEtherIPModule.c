/*
* 	pyEtherIPModule.c
* 	Copyright (C) 2005  Rodrigo Ancavil
*	Email	rancavil@yinnovaser.cl
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
    
#include<Python.h>
#include<stdio.h>
#include<string.h>
#include<errno.h>

#ifdef WIN32

#include<windows.h>
#include<winsock.h>
#include<sys/type.h>

#else

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<sys/ioctl.h>

#endif

#include<stdlib.h>

#define VERSION 2.0
#define SIZE_T 65565

static PyObject *pyEtherError;

/*******************************************/
/* Configure net device to promisc mode    */
/* input  : interface name                 */
/* output : socket                         */
/*******************************************/
static PyObject *promisc(PyObject *self,PyObject *args)
{
 char   *dev;
 int    sock=-1;
 struct ifreq ifr;
 int    n;
 int    uid = 1;
 
 if(!PyArg_ParseTuple(args,"s",&dev)) { 
  	PyErr_SetString(pyEtherError,"trying read parameters");
	return NULL;
 }

 uid = getuid();
 if(uid != 0) {
	PyErr_SetString(pyEtherError,"you must be root");
	return NULL;
 }
 
 sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));
 if(sock<0) {
	 PyErr_SetString(pyEtherError,"can't create socket");
	 return NULL;
 }
 strcpy(ifr.ifr_name,dev);
 n = ioctl(sock,SIOCGIFFLAGS,&ifr);
 if(n<0) {
	 PyErr_SetString(pyEtherError,"can't get FLAGS to configure promisc mode");
	 return NULL;
 }
 ifr.ifr_flags=ifr.ifr_flags|IFF_PROMISC;

 n = ioctl(sock,SIOCSIFFLAGS,&ifr);
 if(n<0) {
	 PyErr_SetString(pyEtherError,"can't set promisc mode");
	 return NULL;
 }
 return Py_BuildValue("i",sock);
}

/***********************************************/
/* Configure net device to normal mode         */
/* input  : interface name                     */
/* output : void                               */
/***********************************************/
static PyObject *noPromisc(PyObject *self,PyObject *args)
{
 char   *dev;
 int    sock=-1;
 struct ifreq ifr;
 int    n;

 if(!PyArg_ParseTuple(args,"si",&dev,&sock)) {
  	 PyErr_SetString(pyEtherError,"trying read parameters");
	 return NULL;
 }
 strcpy(ifr.ifr_name,dev);
 n = ioctl(sock,SIOCGIFFLAGS,&ifr);
 if(n<0) {
	 PyErr_SetString(pyEtherError,"can't get FLAGS to configure promisc mode");
	 return NULL;
 }

 ifr.ifr_flags=ifr.ifr_flags & ~IFF_PROMISC;

 n = ioctl(sock,SIOCSIFFLAGS,&ifr);
 if(n<0) {
	 PyErr_SetString(pyEtherError,"can't set normal mode");
	 return NULL;
 }
 close(sock);

 Py_INCREF(Py_None);
 return Py_None;
}

/****************************************************/
/* Read IP header                                   */
/* input  : socket                                  */
/* output : python dictionary with ip header        */
/****************************************************/
static PyObject *readIPHeader(PyObject *self,PyObject *args) 
{
 int sock;
 unsigned char buffer[SIZE_T];
 unsigned char *ip = (unsigned char *)malloc(20*sizeof(unsigned char)); /* 20 bytes */
 int  n;
 unsigned char version;
 unsigned char ihl;
 unsigned char tos;
 unsigned int  totallength;
 unsigned int  identification;
 unsigned char flags;
 unsigned char fragoffset;
 unsigned int  ttl;
 unsigned int proto;
 unsigned int checksum;
 
 char ipaddr_s[16];
 char ipaddr_d[16];
 
 unsigned char aux = '\0';
 
 if(!PyArg_ParseTuple(args,"i",&sock)) {
  PyErr_SetString(pyEtherError,"trying read parameters");
  close(sock); 
  return NULL;
 }

 ipaddr_s[0] = '\0';
 ipaddr_d[0] = '\0';
 buffer[0] = '\0' ;
 
 n = recvfrom(sock,buffer,SIZE_T,0,NULL,NULL); 
 if(n<42) {
   Py_INCREF(Py_None);
   return Py_None;
 } 
 
 ip = buffer+14;
 if(*ip == 0x45) { 
  version = (ip[0]>>4);
  aux = 0;
  aux = (ip[0]<< 4);
  ihl = aux >> 4;
  tos = ip[1];
  totallength    = (ip[2]<<8)+ip[3]; 
  identification = (ip[4]<<8)+ip[5];
  flags          = (ip[6]>>5);
  aux = 0;
  aux = (ip[6]<<3);
  fragoffset = (aux >> 3) + ip[7];
  ttl = ip[8];
  proto=ip[9];
  checksum=(ip[10]<<8)+ip[11];
  sprintf(ipaddr_s,"%d.%d.%d.%d",ip[12],ip[13],ip[14],ip[15]);
  sprintf(ipaddr_d,"%d.%d.%d.%d",ip[16],ip[17],ip[18],ip[19]);
  return Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s}","version",version,"ihl",ihl,"tos",tos,"len",totallength,\
                                           "ident",identification,"flags",flags,"fragoffset",fragoffset,"ttl",ttl,\
					   "proto",proto,"checksum",checksum,"ipsource",ipaddr_s,"ipdest",ipaddr_d); 
 } else {
   Py_INCREF(Py_None);
   return Py_None;
 }
 Py_INCREF(Py_None);
 return Py_None;
}

/*****************************************************/
/* Read frames through network device configured     */
/* in promisc mode                                   */
/* input  : socket                                   */
/* output : python dictionary ethernet frames        */
/*****************************************************/  
static PyObject *readFrame(PyObject *self,PyObject *args) 
{
 int sock;
 unsigned char buffer[SIZE_T];
 unsigned char *eth  = (unsigned char *)malloc(sizeof(char)*14);  /* 14 bytes */
 unsigned char *ip   = (unsigned char *)malloc(sizeof(char)*20);  /* 20 bytes */
 unsigned char *tcp  = (unsigned char *)malloc(sizeof(char)*8);   /*  8 bytes */
 unsigned char *udp  = (unsigned char *)malloc(sizeof(char)*8);   /*  8 bytes */
 unsigned char *icmp = (unsigned char *)malloc(sizeof(char)*16);  /* 16 bytes */
 int n;

 char ethaddr_s[30];
 char ethaddr_d[30];
 char eth_proto[5];

 char ipaddr_s[16];
 char ipaddr_d[16];
 int  sport=-1;
 int  dport=-1;
 int  proto=-1;

 int  icmptype = -1;
 int  icmpcode = -1;

 if(!PyArg_ParseTuple(args,"i",&sock)) {
  PyErr_SetString(pyEtherError,"trying read parameters");
  close(sock); 
  return NULL;
 }
 
 ethaddr_s[0] = '\0';
 ethaddr_d[0] = '\0';
 ipaddr_s[0] = '\0';
 ipaddr_d[0] = '\0';
 buffer[0] = '\0' ;
 eth = NULL;
 ip  = NULL;
 tcp = NULL;
 udp = NULL;

 n = recvfrom(sock,buffer,SIZE_T,0,NULL,NULL);
 if(n<42) {
   Py_INCREF(Py_None);
   return Py_None;
 } 

 eth = buffer;
 sprintf(ethaddr_d,"%02X:%02X:%02X:%02X:%02X:%02X",eth[0],eth[1],eth[2],eth[3],eth[4],eth[5]);
 sprintf(ethaddr_s,"%02X:%02X:%02X:%02X:%02X:%02X",eth[6],eth[7],eth[8],eth[9],eth[10],eth[11]);
 sprintf(eth_proto,"%X",(eth[12]<<8)+eth[13]);
 
 ip = buffer+14;
 if(*ip == 0x45) {
 	proto=ip[9];
  	sprintf(ipaddr_s,"%d.%d.%d.%d",ip[12],ip[13],ip[14],ip[15]);
  	sprintf(ipaddr_d,"%d.%d.%d.%d",ip[16],ip[17],ip[18],ip[19]);

  	if(proto == 6) {
    		tcp = ip+20;
    		sport = (tcp[0]<<8)+tcp[1];
    		dport = (tcp[2]<<8)+tcp[3];
    		return Py_BuildValue("{s:s,s:s,s:s,s:s,s:s,s:i,s:i,s:i}",\
				     "ethaddr_s",ethaddr_s,\
				     "ethaddr_d",ethaddr_d,\
				     "eth_proto",eth_proto,\
				     "idpaddr_s",ipaddr_s,\
				     "ipaddr_d",ipaddr_d,\
				     "proto",proto,\
				     "s_port",sport,\
				     "d_port",dport); 
  	}
  	if(proto == 17) {
    		udp = ip+20;
    		sport = (udp[0]<<8)+udp[1];
    		dport = (udp[2]<<8)+udp[3];
    		return Py_BuildValue("{s:s,s:s,s:s,s:s,s:s,s:i,s:i,s:i}",\
				     "ethaddr_s",ethaddr_s,\
				     "ethaddr_d",ethaddr_d,\
				     "eth_proto",eth_proto,\
				     "ipaddr_s",ipaddr_s,\
				     "ipaddr_d",ipaddr_d,\
				     "proto",proto,\
				     "s_port",sport,\
				     "d_port",dport); 
  	}
  	if(proto == 1) {
     		icmp = ip+20;
     		icmptype = icmp[0];
     		icmpcode = icmp[1];
     		return Py_BuildValue("{s:s,s:s,s:s,s:s,s:s,s:i,s:i,s:i}",\
				     "ethaddr_s",ethaddr_s,\
				     "ethaddr_d",ethaddr_d,\
				     "eth_proto",eth_proto,\
				     "ipaddr_s",ipaddr_s,\
				     "ipaddr_d",ipaddr_d,\
				     "proto",proto,\
				     "icmptype",icmptype,\
				     "icmpcode",icmpcode); 
  	}
  } else {
          Py_INCREF(Py_None);
          return Py_None;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

struct module_state {
    PyObject *error;
};
#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif


static PyObject *error_out(PyObject *m) {
    struct module_state *st = GETSTATE(m);
    PyErr_SetString(st->error, "something bad happened");
    return NULL;
}

static PyMethodDef Methods[] = {
 {"promisc",promisc,METH_VARARGS,"Config network device to promisc mode"},
 {"noPromisc",noPromisc,METH_VARARGS,"Back network device to normal mode"},
 {"readIPHeader",readIPHeader,METH_VARARGS,"Read IP Headers"},
 {"readFrame",readFrame,METH_VARARGS,"Read Ethernet Frames"},
 {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
 {NULL,NULL,0,NULL}
};

#if PY_MAJOR_VERSION >= 3

static int pyEtherIP_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int pyEtherIP_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "pyEtherIP",
        NULL,
        sizeof(struct module_state),
        Methods,
        NULL,
        pyEtherIP_traverse,
        pyEtherIP_clear,
        NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC
PyInit_pyEtherIP(void)

#else
#define INITERROR return

void initpyEtherIP(void) 
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject *mod = PyModule_Create(&moduledef);
#else
    PyObject *mod = Py_InitModule("pyEtherIP",Methods);
    PyObject *exc = PyModule_GetDict(mod);
    pyEtherError = PyErr_NewException("pyEtherIP.pyEtherError",NULL,NULL);
    PyDict_SetItemString(exc,"pyEtherError",pyEtherError);
#endif

if (mod == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(mod);

    st->error = PyErr_NewException("pyEtherIP.pyEtherError", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(mod);
        INITERROR;
    }

#if PY_MAJOR_VERSION >= 3
    return mod;
#endif
}
