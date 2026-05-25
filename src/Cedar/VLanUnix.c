// SoftEther VPN Source Code - Stable Edition Repository
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// Contributors:
// - nattoheaven (https://github.com/nattoheaven)
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// VLanUnix.c
// Virtual device driver library for UNIX

#include <GlobalConst.h>

#ifdef	VLAN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#ifdef	UNIX_MACOS
#include <net/ethernet.h>
#include <net/bpf.h>
#include <net/if.h>
#include <fcntl.h>
#endif

#ifdef	OS_UNIX

static LIST *unix_vlan = NULL;

#ifndef	NO_VLAN

// Get the PACKET_ADAPTER
PACKET_ADAPTER *VLanGetPacketAdapter()
{
	PACKET_ADAPTER *pa;

	pa = NewPacketAdapter(VLanPaInit, VLanPaGetCancel,
		VLanPaGetNextPacket, VLanPaPutPacket, VLanPaFree);
	if (pa == NULL)
	{
		return NULL;
	}

	return pa;
}

// PA initialization
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	// Connect to the driver
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// Failure
		return false;
	}

	s->PacketAdapter->Param = v;

	return true;
}

// Get the cancel object
CANCEL *VLanPaGetCancel(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return NULL;
	}

	return VLanGetCancel(v);
}

// Release the packet adapter
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// End the virtual LAN card
	FreeVLan(v);

	s->PacketAdapter->Param = NULL;
}

// Write a packet
bool VLanPaPutPacket(SESSION *s, void *data, UINT size)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return false;
	}

	return VLanPutPacket(v, data, size);
}

// Get the next packet
UINT VLanPaGetNextPacket(SESSION *s, void **data)
{
	VLAN *v;
	UINT size;
	// Validate arguments
	if (data == NULL || (s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return INFINITE;
	}

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
}

// Write a packet to the virtual LAN card
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
	UINT ret;
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}
	if (buf == NULL || size == 0)
	{
		if (buf != NULL)
		{
			Free(buf);
		}
		return true;
	}

	ret = write(v->fd, buf, size);

	if (ret >= 1)
	{
		Free(buf);
		return true;
	}

	if (errno == EAGAIN || ret == 0)
	{
		Free(buf);
		return true;
	}

	return false;
}

// Get the next packet from the virtual LAN card
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	UCHAR tmp[TAP_READ_BUF_SIZE];
	int ret;
	// Validate arguments
	if (v == NULL || buf == NULL || size == 0)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

#ifdef	UNIX_MACOS
	// On macOS the fd is a BPF descriptor: each read() returns zero or more
	// frames, each prefixed by a struct bpf_hdr and padded to BPF_WORDALIGN.
	// Hand out one frame per call, refilling the buffer when it drains.
	while (true)
	{
		struct bpf_hdr *bh;
		UCHAR *frame;
		UINT caplen;

		if (v->BpfBufferOff < v->BpfBufferUsed)
		{
			bh = (struct bpf_hdr *)(v->BpfBuffer + v->BpfBufferOff);
			caplen = bh->bh_caplen;
			frame = v->BpfBuffer + v->BpfBufferOff + bh->bh_hdrlen;
			v->BpfBufferOff += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

			if (caplen == 0 || caplen > TAP_READ_BUF_SIZE)
			{
				// Skip empty / oversized frames
				continue;
			}

			*buf = Malloc(caplen);
			Copy(*buf, frame, caplen);
			*size = caplen;
			return true;
		}

		// Buffer drained: pull a fresh batch
		ret = read(v->fd, v->BpfBuffer, v->BpfBufferSize);
		if (ret == 0 || (ret == -1 && errno == EAGAIN))
		{
			// No packet
			*buf = NULL;
			*size = 0;
			return true;
		}
		else if (ret == -1)
		{
			return false;
		}

		v->BpfBufferUsed = ret;
		v->BpfBufferOff = 0;
	}
#else	// UNIX_MACOS
	// Read
	ret = read(v->fd, tmp, sizeof(tmp));

	if (ret == 0 ||
		(ret == -1 && errno == EAGAIN))
	{
		// No packet
		*buf = NULL;
		*size = 0;
		return true;
	}
	else if (ret == -1 || ret > TAP_READ_BUF_SIZE)
	{
		// Error
		return false;
	}
	else
	{
		// Reading packet success
		*buf = Malloc(ret);
		Copy(*buf, tmp, ret);
		*size = ret;
		return true;
	}
#endif	// UNIX_MACOS
}

// Get the cancel object
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	int fd;
	int yes = 0;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	fd = v->fd;

	UnixSetSocketNonBlockingMode(fd, true);

	c->SpecialFlag = true;
	c->pipe_read = fd;

	return c;
}

// Close the Virtual LAN card
void FreeVLan(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Free(v->InstanceName);

#ifdef	UNIX_MACOS
	if (v->BpfBuffer != NULL)
	{
		Free(v->BpfBuffer);
	}
#endif	// UNIX_MACOS

	Free(v);
}

#ifdef	UNIX_MACOS
// Allocate the per-VLAN BPF read buffer, sized to the kernel's bpf buffer length
static void UnixVLanInitBpfBuffer(VLAN *v)
{
	UINT blen = 0;

	if (v == NULL)
	{
		return;
	}

	if (ioctl(v->fd, BIOCGBLEN, &blen) < 0 || blen == 0)
	{
		blen = MACOS_BPF_BUFSIZE;
	}

	v->BpfBuffer = Malloc(blen);
	v->BpfBufferSize = blen;
	v->BpfBufferUsed = 0;
	v->BpfBufferOff = 0;
}
#endif	// UNIX_MACOS

// Create a tap
VLAN *NewTap(char *name, char *mac_address)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (name == NULL || mac_address == NULL)
	{
		return NULL;
	}

	fd = UnixCreateTapDeviceEx(name, "tap", mac_address);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(name);
	v->fd = fd;

#ifdef	UNIX_MACOS
	UnixVLanInitBpfBuffer(v);
#endif	// UNIX_MACOS

	return v;
}

// Close the tap
void FreeTap(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Routes through UnixCloseTapDevice so the macOS feth pair is torn down too
	UnixCloseTapDevice(v->fd);
	FreeVLan(v);
}

// Get the Virtual LAN card list
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (instance_name == NULL)
	{
		return NULL;
	}

	// Open the tap
	fd = UnixVLanGet(instance_name);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(instance_name);
	v->fd = fd;

#ifdef	UNIX_MACOS
	UnixVLanInitBpfBuffer(v);
#endif	// UNIX_MACOS

	return v;
}

#ifdef	UNIX_MACOS

// macOS has no usable tap kext on Apple Silicon. Instead we build an
// equivalent L2 endpoint out of a feth (if_fake) peer pair plus a /dev/bpf
// descriptor, which needs no kernel extension:
//
//   <host feth>  <== peer ==>  <dev feth>  <-- BPF attached here
//
// The OS treats the host-side feth as the VPN virtual NIC (the user assigns
// it an IP / DHCP). Frames the OS transmits on the host feth arrive on the
// dev feth, where BPF read() delivers them to us. Frames we BPF write() on
// the dev feth are delivered to the host feth as if received, reaching the
// host IP stack. This was validated by poc/feth_bpf_poc.c.

// fd -> feth interface names, so we can destroy the pair on close.
// Only the create/destroy (cold) paths touch this list.
typedef struct MACOS_FETH_ENTRY
{
	int fd;
	char host[16];	// host-side feth (carries the IP, OS routes through it)
	char dev[16];	// dev-side feth (BPF attached)
} MACOS_FETH_ENTRY;

static LIST *macos_feth_list = NULL;

static void MacOsFethInit()
{
	if (macos_feth_list == NULL)
	{
		macos_feth_list = NewList(NULL);
	}
}

// Run "ifconfig <args>" and return the first output line (caller frees), or NULL.
static char *MacOsIfconfig(char *args, bool capture)
{
	char cmd[MAX_SIZE];
	TOKEN_LIST *t;
	char *ret = NULL;

	Format(cmd, sizeof(cmd), "/sbin/ifconfig %s 2>/dev/null", args);
	t = UnixExec(cmd);
	if (t != NULL)
	{
		if (capture && t->NumTokens >= 1)
		{
			ret = CopyStr(t->Token[0]);
		}
		FreeToken(t);
	}
	return ret;
}

// Open a /dev/bpf device and bind it to the given interface.
static int MacOsOpenBpf(char *ifname)
{
	char dev[32];
	int fd = -1;
	int i;
	UINT blen = MACOS_BPF_BUFSIZE;
	UINT yes = 1, no = 0;
	struct ifreq ifr;

	for (i = 0; i < 256; i++)
	{
		Format(dev, sizeof(dev), "/dev/bpf%d", i);
		fd = open(dev, O_RDWR);
		if (fd >= 0)
		{
			break;
		}
		if (errno == EBUSY)
		{
			continue;
		}
		if (errno == ENOENT)
		{
			break;
		}
	}
	if (fd < 0)
	{
		return -1;
	}

	// Buffer length must be set before BIOCSETIF
	ioctl(fd, BIOCSBLEN, &blen);

	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
	if (ioctl(fd, BIOCSETIF, &ifr) < 0)
	{
		close(fd);
		return -1;
	}

	ioctl(fd, BIOCIMMEDIATE, &yes);	// return as soon as a packet arrives
	ioctl(fd, BIOCSHDRCMPLT, &yes);	// we supply complete link-layer headers
	ioctl(fd, BIOCSSEESENT, &no);	// don't loop back our own injected frames

	return fd;
}

// Create a feth peer pair, attach BPF, return the bpf fd (or -1).
static int MacOsCreateTap(UCHAR *mac_address)
{
	char *host = NULL, *dev = NULL;
	char args[MAX_SIZE];
	int fd = -1;
	MACOS_FETH_ENTRY *e;

	MacOsFethInit();

	// Auto-allocate two feth interfaces (ifconfig prints the chosen name)
	host = MacOsIfconfig("feth create", true);
	dev = MacOsIfconfig("feth create", true);
	if (host == NULL || dev == NULL || host[0] == 0 || dev[0] == 0)
	{
		goto FAILED;
	}

	// Peer them
	Format(args, sizeof(args), "%s peer %s", host, dev);
	MacOsIfconfig(args, false);

	// The OS originates frames on the host feth, so its MAC must be the
	// virtual NIC MAC that the VPN side sees.
	if (mac_address != NULL)
	{
		Format(args, sizeof(args), "%s lladdr %02x:%02x:%02x:%02x:%02x:%02x",
			host, mac_address[0], mac_address[1], mac_address[2],
			mac_address[3], mac_address[4], mac_address[5]);
		MacOsIfconfig(args, false);
	}

	// Bring both up
	Format(args, sizeof(args), "%s up", host);
	MacOsIfconfig(args, false);
	Format(args, sizeof(args), "%s up", dev);
	MacOsIfconfig(args, false);

	// Attach BPF to the dev side
	fd = MacOsOpenBpf(dev);
	if (fd == -1)
	{
		goto FAILED;
	}

	e = ZeroMalloc(sizeof(MACOS_FETH_ENTRY));
	e->fd = fd;
	StrCpy(e->host, sizeof(e->host), host);
	StrCpy(e->dev, sizeof(e->dev), dev);
	Add(macos_feth_list, e);

	Debug("MacOsCreateTap: host=%s dev=%s bpf_fd=%d\n", host, dev, fd);

	Free(host);
	Free(dev);
	return fd;

FAILED:
	if (host != NULL)
	{
		Format(args, sizeof(args), "%s destroy", host);
		MacOsIfconfig(args, false);
		Free(host);
	}
	if (dev != NULL)
	{
		Format(args, sizeof(args), "%s destroy", dev);
		MacOsIfconfig(args, false);
		Free(dev);
	}
	return -1;
}

// Destroy the feth pair associated with the given bpf fd.
static void MacOsDestroyTap(int fd)
{
	UINT i;
	char args[MAX_SIZE];

	if (macos_feth_list == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(macos_feth_list); i++)
	{
		MACOS_FETH_ENTRY *e = LIST_DATA(macos_feth_list, i);
		if (e->fd == fd)
		{
			Format(args, sizeof(args), "%s destroy", e->host);
			MacOsIfconfig(args, false);
			Format(args, sizeof(args), "%s destroy", e->dev);
			MacOsIfconfig(args, false);
			Delete(macos_feth_list, e);
			Free(e);
			break;
		}
	}
}

#endif	// UNIX_MACOS

// Create a tap device
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	int fd;
	struct ifreq ifr;
	char eth_name[MAX_SIZE];
	char instance_name_lower[MAX_SIZE];
	struct sockaddr sa;
	char *tap_name = TAP_FILENAME_1;
	int s;
#ifdef	UNIX_MACOS
	char tap_macos_name[256] = TAP_MACOS_DIR TAP_MACOS_FILENAME;
#endif
	// Validate arguments
	if (name == NULL)
	{
		return -1;
	}

	// Generate the device name
	StrCpy(instance_name_lower, sizeof(instance_name_lower), name);
	Trim(instance_name_lower);
	StrLower(instance_name_lower);
	Format(eth_name, sizeof(eth_name), "%s_%s", prefix, instance_name_lower);

	eth_name[15] = 0;

#ifdef	UNIX_MACOS
	// macOS: build the L2 endpoint from a feth pair + BPF (no kext required).
	return MacOsCreateTap(mac_address);
#endif	// UNIX_MACOS

	// Open the tun / tap
#ifndef	UNIX_MACOS
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		// Linux
		if (IsFile(TAP_FILENAME_1) == false)
		{
			char tmp[MAX_SIZE];

			Format(tmp, sizeof(tmp), "%s c 10 200", TAP_FILENAME_1);
			Run("mknod", tmp, true, true);

			Format(tmp, sizeof(tmp), "600 %s", TAP_FILENAME_1);
			Run("chmod", tmp, true, true);
		}
	}
	// Other than MacOS X
	fd = open(TAP_FILENAME_1, O_RDWR);
	if (fd == -1)
	{
		// Failure
		fd = open(TAP_FILENAME_2, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
		tap_name = TAP_FILENAME_2;
	}
#else	// UNIX_MACOS
	{
		int i;
		fd = -1;
		for (i = 0; i < TAP_MACOS_NUMBER; i++) {
			sprintf(tap_macos_name + strlen(TAP_MACOS_DIR TAP_MACOS_FILENAME), "%d", i);
			fd = open(tap_macos_name, O_RDWR);
			if (fd != -1)
			{
				tap_name = tap_macos_name;
				break;
			}
		}
		if (fd == -1)
		{
			return -1;
		}
	}
#endif	// UNIX_MACOS

#ifdef	UNIX_LINUX
	// Create a tap for Linux

	// Set the device name
	Zero(&ifr, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
	{
		// Failure
		close(fd);
		return -1;
	}

	// MAC address setting
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
			ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
			Copy(&ifr.ifr_addr.sa_data, mac_address, 6);
			ioctl(s, SIOCSIFHWADDR, &ifr);
		}

		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
		ioctl(s, SIOCGIFFLAGS, &ifr);

		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);

		close(s);
	}

#else	// UNIX_LINUX
#ifdef	UNIX_MACOS
	// MAC address setting
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		char *macos_eth_name;
		macos_eth_name = tap_macos_name + strlen(TAP_MACOS_DIR);

		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), macos_eth_name);
			ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
			ifr.ifr_addr.sa_family = AF_LINK;
			Copy(&ifr.ifr_addr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFLLADDR, &ifr);
		}

		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), macos_eth_name);
		ioctl(s, SIOCGIFFLAGS, &ifr);

		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);

		close(s);
	}
#endif	// UNIX_MACOS
#ifdef	UNIX_SOLARIS
	// Create a tap for Solaris
	{
		int ip_fd;
		int tun_fd;
		int ppa;

		tun_fd = open(tap_name, O_RDWR);
		if (tun_fd == -1)
		{
			// Failure
			close(fd);
			return -1;
		}

		ip_fd = open("/dev/ip", O_RDWR);
		if (ip_fd == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			return -1;
		}

		ppa = -1;
		ppa = ioctl(tun_fd, TUNNEWPPA, ppa);
		if (ppa == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, I_PUSH, "ip") < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, IF_UNITSEL, (char *)&ppa) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(ip_fd, I_LINK, fd) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		close(tun_fd);
		close(ip_fd);
	}

#endif	// UNIX_SOLARIS
#endif	// UNIX_LINUX

	return fd;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
{
	return UnixCreateTapDeviceEx(name, "vpn", mac_address);
}

// Close the tap device
void UnixCloseTapDevice(int fd)
{
	// Validate arguments
	if (fd == -1)
	{
		return;
	}

#ifdef	UNIX_MACOS
	// Tear down the feth pair backing this bpf descriptor
	MacOsDestroyTap(fd);
#endif	// UNIX_MACOS

	close(fd);
}

#else	// NO_VLAN

void UnixCloseTapDevice(int fd)
{
}

int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	return -1;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
{
	return -1;
}

#endif	// NO_VLAN

// Comparison of the VLAN list entries
int UnixCompareVLan(void *p1, void *p2)
{
	UNIX_VLAN_LIST *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN_LIST **)p1;
	v2 = *(UNIX_VLAN_LIST **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// Initialize the VLAN list
void UnixVLanInit()
{
	unix_vlan = NewList(UnixCompareVLan);
}

// Create a VLAN
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address)
{
	// Validate arguments
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	name = tmp;

	LockList(unix_vlan);
	{
		UNIX_VLAN_LIST *t, tt;
		int fd;

		// Check whether a device with the same name exists
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			// Already exist
			UnlockList(unix_vlan);
			return false;
		}

		// Create a tap device
		fd = UnixCreateTapDeviceEx(name, prefix, mac_address);
		if (fd == -1)
		{
			// Failure to create
			UnlockList(unix_vlan);
			return false;
		}

		t = ZeroMalloc(sizeof(UNIX_VLAN_LIST));
		t->fd = fd;
		StrCpy(t->Name, sizeof(t->Name), name);

		Insert(unix_vlan, t);
	}
	UnlockList(unix_vlan);

	return true;
}
bool UnixVLanCreate(char *name, UCHAR *mac_address)
{
	return UnixVLanCreateEx(name, "vpn", mac_address);
}

// Enumerate VLANs
TOKEN_LIST *UnixVLanEnum()
{
	TOKEN_LIST *ret;
	UINT i;
	if (unix_vlan == NULL)
	{
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	LockList(unix_vlan);
	{
		ret->NumTokens = LIST_NUM(unix_vlan);
		ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

		for (i = 0;i < ret->NumTokens;i++)
		{
			UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

			ret->Token[i] = CopyStr(t->Name);
		}
	}
	UnlockList(unix_vlan);

	return ret;
}

// Delete the VLAN
void UnixVLanDelete(char *name)
{
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			UnixCloseTapDevice(t->fd);
			Delete(unix_vlan, t);
			Free(t);
		}
	}
	UnlockList(unix_vlan);
}

// Get the VLAN
int UnixVLanGet(char *name)
{
	int fd = -1;
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return -1;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			fd = t->fd;
		}
	}
	UnlockList(unix_vlan);

	return fd;
}

// Release the VLAN list
void UnixVLanFree()
{
	UINT i;

	for (i = 0;i < LIST_NUM(unix_vlan);i++)
	{
		UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

		UnixCloseTapDevice(t->fd);
		Free(t);
	}

	ReleaseList(unix_vlan);
	unix_vlan = NULL;
}

#endif	// OS_UNIX

#endif	// VLAN_C

