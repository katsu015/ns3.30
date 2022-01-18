/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Yufei Cheng
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Yufei Cheng   <yfcheng@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#include <vector>
#include "ns3/ptr.h"
#include "ns3/boolean.h"
#include "ns3/test.h"
#include "ns3/ipv4-route.h"
#include "ns3/mesh-helper.h"
#include "ns3/simulator.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/ipv4-address-helper.h"

#include "ns3/youngdsr-fs-header.h"
#include "ns3/youngdsr-option-header.h"
#include "ns3/youngdsr-rreq-table.h"
#include "ns3/youngdsr-rcache.h"
#include "ns3/youngdsr-rsendbuff.h"
#include "ns3/youngdsr-main-helper.h"
#include "ns3/youngdsr-helper.h"

using namespace ns3;
using namespace youngdsr;

// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr
 * \defgroup youngdsr-test DSR routing module tests
 */


/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrFsHeaderTest
 * \brief Unit test for DSR Fixed Size Header
 */
class YoungdsrFsHeaderTest : public TestCase
{
public:
  YoungdsrFsHeaderTest ();
  ~YoungdsrFsHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrFsHeaderTest::YoungdsrFsHeaderTest ()
  : TestCase ("DSR Fixed size Header")
{
}
YoungdsrFsHeaderTest::~YoungdsrFsHeaderTest ()
{
}
void
YoungdsrFsHeaderTest::DoRun ()
{
  youngdsr::YoungdsrRoutingHeader header;
  youngdsr::YoungdsrOptionRreqHeader rreqHeader;
  header.AddYoungdsrOption (rreqHeader); // has an alignment of 4n+0

  NS_TEST_EXPECT_MSG_EQ (header.GetSerializedSize () % 2, 0, "length of routing header is not a multiple of 4");
  Buffer buf;
  buf.AddAtStart (header.GetSerializedSize ());
  header.Serialize (buf.Begin ());

  const uint8_t* data = buf.PeekData ();
  NS_TEST_EXPECT_MSG_EQ (*(data + 8), rreqHeader.GetType (), "expect the rreqHeader after fixed size header");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrRreqHeaderTest
 * \brief Unit test for RREQ
 */
class YoungdsrRreqHeaderTest : public TestCase
{
public:
  YoungdsrRreqHeaderTest ();
  ~YoungdsrRreqHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrRreqHeaderTest::YoungdsrRreqHeaderTest ()
  : TestCase ("DSR RREQ")
{
}
YoungdsrRreqHeaderTest::~YoungdsrRreqHeaderTest ()
{
}
void
YoungdsrRreqHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionRreqHeader h;
  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));

  h.SetTarget (Ipv4Address ("1.1.1.3"));
  NS_TEST_EXPECT_MSG_EQ (h.GetTarget (), Ipv4Address ("1.1.1.3"), "trivial");
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");
  h.SetId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  youngdsr::YoungdsrOptionRreqHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 20, "Total RREP is 20 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrRrepHeaderTest
 * \brief Unit test for RREP
 */
class YoungdsrRrepHeaderTest : public TestCase
{
public:
  YoungdsrRrepHeaderTest ();
  ~YoungdsrRrepHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrRrepHeaderTest::YoungdsrRrepHeaderTest ()
  : TestCase ("DSR RREP")
{
}
YoungdsrRrepHeaderTest::~YoungdsrRrepHeaderTest ()
{
}
void
YoungdsrRrepHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionRrepHeader h;

  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  youngdsr::YoungdsrOptionRrepHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 16, "Total RREP is 16 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrSRHeaderTest
 * \brief Unit test for Source Route
 */
class YoungdsrSRHeaderTest : public TestCase
{
public:
  YoungdsrSRHeaderTest ();
  ~YoungdsrSRHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrSRHeaderTest::YoungdsrSRHeaderTest ()
  : TestCase ("DSR Source Route")
{
}
YoungdsrSRHeaderTest::~YoungdsrSRHeaderTest ()
{
}
void
YoungdsrSRHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionSRHeader h;
  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");

  h.SetSalvage (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetSalvage (), 1, "trivial");
  h.SetSegmentsLeft (2);
  NS_TEST_EXPECT_MSG_EQ (h.GetSegmentsLeft (), 2, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  youngdsr::YoungdsrOptionSRHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 16, "Total RREP is 16 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrRerrHeaderTest
 * \brief Unit test for RERR
 */
class YoungdsrRerrHeaderTest : public TestCase
{
public:
  YoungdsrRerrHeaderTest ();
  ~YoungdsrRerrHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrRerrHeaderTest::YoungdsrRerrHeaderTest ()
  : TestCase ("DSR RERR")
{
}
YoungdsrRerrHeaderTest::~YoungdsrRerrHeaderTest ()
{
}
void
YoungdsrRerrHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionRerrUnreachHeader h;
  h.SetErrorSrc (Ipv4Address ("1.1.1.0"));
  NS_TEST_EXPECT_MSG_EQ (h.GetErrorSrc (), Ipv4Address ("1.1.1.0"), "trivial");
  h.SetErrorDst (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (h.GetErrorDst (), Ipv4Address ("1.1.1.1"), "trivial");
  h.SetSalvage (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetSalvage (), 1, "trivial");
  h.SetUnreachNode (Ipv4Address ("1.1.1.2"));
  NS_TEST_EXPECT_MSG_EQ (h.GetUnreachNode (), Ipv4Address ("1.1.1.2"), "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  youngdsr::YoungdsrOptionRerrUnreachHeader h2;
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 20, "Total RREP is 20 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrAckReqHeaderTest
 * \brief Unit test for ACK-REQ
 */
class YoungdsrAckReqHeaderTest : public TestCase
{
public:
  YoungdsrAckReqHeaderTest ();
  ~YoungdsrAckReqHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrAckReqHeaderTest::YoungdsrAckReqHeaderTest ()
  : TestCase ("DSR Ack Req")
{
}
YoungdsrAckReqHeaderTest::~YoungdsrAckReqHeaderTest ()
{
}
void
YoungdsrAckReqHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionAckReqHeader h;

  h.SetAckId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetAckId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  p->AddHeader (header);
  youngdsr::YoungdsrOptionAckReqHeader h2;
  p->RemoveAtStart (8);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 4, "Total RREP is 4 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrAckHeaderTest
 * \brief Unit test for ACK
 */
class YoungdsrAckHeaderTest : public TestCase
{
public:
  YoungdsrAckHeaderTest ();
  ~YoungdsrAckHeaderTest ();
  virtual void
  DoRun (void);
};
YoungdsrAckHeaderTest::YoungdsrAckHeaderTest ()
  : TestCase ("DSR ACK")
{
}
YoungdsrAckHeaderTest::~YoungdsrAckHeaderTest ()
{
}
void
YoungdsrAckHeaderTest::DoRun ()
{
  youngdsr::YoungdsrOptionAckHeader h;

  h.SetRealSrc (Ipv4Address ("1.1.1.0"));
  NS_TEST_EXPECT_MSG_EQ (h.GetRealSrc (), Ipv4Address ("1.1.1.0"), "trivial");
  h.SetRealDst (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (h.GetRealDst (), Ipv4Address ("1.1.1.1"), "trivial");
  h.SetAckId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetAckId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  youngdsr::YoungdsrRoutingHeader header;
  header.AddYoungdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  p->AddHeader (header);
  youngdsr::YoungdsrOptionAckHeader h2;
  p->RemoveAtStart (8);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 12, "Total RREP is 12 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrCacheEntryTest
 * \brief Unit test for DSR route cache entry
 */
class YoungdsrCacheEntryTest : public TestCase
{
public:
  YoungdsrCacheEntryTest ();
  ~YoungdsrCacheEntryTest ();
  virtual void
  DoRun (void);
};
YoungdsrCacheEntryTest::YoungdsrCacheEntryTest ()
  : TestCase ("DSR ACK")
{
}
YoungdsrCacheEntryTest::~YoungdsrCacheEntryTest ()
{
}
void
YoungdsrCacheEntryTest::DoRun ()
{
  Ptr<youngdsr::YoungdsrRouteCache> rcache = CreateObject<youngdsr::YoungdsrRouteCache> ();
  std::vector<Ipv4Address> ip;
  ip.push_back (Ipv4Address ("0.0.0.0"));
  ip.push_back (Ipv4Address ("0.0.0.1"));
  Ipv4Address dst = Ipv4Address ("0.0.0.1");
  youngdsr::YoungdsrRouteCacheEntry entry (ip, dst, Seconds (1));
  NS_TEST_EXPECT_MSG_EQ (entry.GetVector ().size (), 2, "trivial");
  NS_TEST_EXPECT_MSG_EQ (entry.GetDestination (), Ipv4Address ("0.0.0.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (entry.GetExpireTime (), Seconds (1), "trivial");

  entry.SetExpireTime (Seconds (3));
  NS_TEST_EXPECT_MSG_EQ (entry.GetExpireTime (), Seconds (3), "trivial");
  entry.SetDestination (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (entry.GetDestination (), Ipv4Address ("1.1.1.1"), "trivial");
  ip.push_back (Ipv4Address ("0.0.0.2"));
  entry.SetVector (ip);
  NS_TEST_EXPECT_MSG_EQ (entry.GetVector ().size (), 3, "trivial");

  NS_TEST_EXPECT_MSG_EQ (rcache->AddRoute (entry), true, "trivial");

  std::vector<Ipv4Address> ip2;
  ip2.push_back (Ipv4Address ("1.1.1.0"));
  ip2.push_back (Ipv4Address ("1.1.1.1"));
  Ipv4Address dst2 = Ipv4Address ("1.1.1.1");
  youngdsr::YoungdsrRouteCacheEntry entry2 (ip2, dst2, Seconds (2));
  youngdsr::YoungdsrRouteCacheEntry newEntry;
  NS_TEST_EXPECT_MSG_EQ (rcache->AddRoute (entry2), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->LookupRoute (dst2, newEntry), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("2.2.2.2")), false, "trivial");

  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("1.1.1.1")), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("1.1.1.1")), false, "trivial");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrSendBuffTest
 * \brief Unit test for Send Buffer
 */
class YoungdsrSendBuffTest : public TestCase
{
public:
  YoungdsrSendBuffTest ();
  ~YoungdsrSendBuffTest ();
  virtual void
  DoRun (void);
  /// Check size limit function
  void CheckSizeLimit ();
  /// Check timeout function
  void CheckTimeout ();

  youngdsr::YoungdsrSendBuffer q; ///< send buffer
};
YoungdsrSendBuffTest::YoungdsrSendBuffTest ()
  : TestCase ("DSR SendBuff"),
    q ()
{
}
YoungdsrSendBuffTest::~YoungdsrSendBuffTest ()
{
}
void
YoungdsrSendBuffTest::DoRun ()
{
  q.SetMaxQueueLen (32);
  NS_TEST_EXPECT_MSG_EQ (q.GetMaxQueueLen (), 32, "trivial");
  q.SetSendBufferTimeout (Seconds (10));
  NS_TEST_EXPECT_MSG_EQ (q.GetSendBufferTimeout (), Seconds (10), "trivial");

  Ptr<const Packet> packet = Create<Packet> ();
  Ipv4Address dst1 = Ipv4Address ("0.0.0.1");
  youngdsr::YoungdsrSendBuffEntry e1 (packet, dst1, Seconds (1));
  q.Enqueue (e1);
  q.Enqueue (e1);
  q.Enqueue (e1);
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.1")), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("1.1.1.1")), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 1, "trivial");
  q.DropPacketWithDst (Ipv4Address ("0.0.0.1"));
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.1")), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 0, "trivial");

  Ipv4Address dst2 = Ipv4Address ("0.0.0.2");
  youngdsr::YoungdsrSendBuffEntry e2 (packet, dst2, Seconds (1));
  q.Enqueue (e1);
  q.Enqueue (e2);
  Ptr<Packet> packet2 = Create<Packet> ();
  youngdsr::YoungdsrSendBuffEntry e3 (packet2, dst2, Seconds (1));
  NS_TEST_EXPECT_MSG_EQ (q.Dequeue (Ipv4Address ("0.0.0.3"), e3), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Dequeue (Ipv4Address ("0.0.0.2"), e3), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.2")), false, "trivial");
  q.Enqueue (e2);
  q.Enqueue (e3);
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 2, "trivial");
  Ptr<Packet> packet4 = Create<Packet> ();
  Ipv4Address dst4 = Ipv4Address ("0.0.0.4");
  youngdsr::YoungdsrSendBuffEntry e4 (packet4, dst4, Seconds (20));
  q.Enqueue (e4);
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");
  q.DropPacketWithDst (Ipv4Address ("0.0.0.4"));
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 2, "trivial");

  CheckSizeLimit ();

  Simulator::Schedule (q.GetSendBufferTimeout () + Seconds (1), &YoungdsrSendBuffTest::CheckTimeout, this);

  Simulator::Run ();
  Simulator::Destroy ();
}
void
YoungdsrSendBuffTest::CheckSizeLimit ()
{
  Ptr<Packet> packet = Create<Packet> ();
  Ipv4Address dst;
  youngdsr::YoungdsrSendBuffEntry e1 (packet, dst, Seconds (1));

  for (uint32_t i = 0; i < q.GetMaxQueueLen (); ++i)
    {
      q.Enqueue (e1);
    }
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");

  for (uint32_t i = 0; i < q.GetMaxQueueLen (); ++i)
    {
      q.Enqueue (e1);
    }
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");
}
void
YoungdsrSendBuffTest::CheckTimeout ()
{
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 0, "Must be empty now");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrRreqTableTest
 * \brief Unit test for DSR routing table entry
 */
class YoungdsrRreqTableTest : public TestCase
{
public:
  YoungdsrRreqTableTest ();
  ~YoungdsrRreqTableTest ();
  virtual void
  DoRun (void);
};
YoungdsrRreqTableTest::YoungdsrRreqTableTest ()
  : TestCase ("DSR RreqTable")
{
}
YoungdsrRreqTableTest::~YoungdsrRreqTableTest ()
{
}
void
YoungdsrRreqTableTest::DoRun ()
{
  youngdsr::RreqTableEntry rt;

  rt.m_reqNo = 2;
  NS_TEST_EXPECT_MSG_EQ (rt.m_reqNo, 2, "trivial");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup youngdsr-test
 * \ingroup tests
 *
 * \class YoungdsrTestSuite
 * \brief DSR test suite
 */
class YoungdsrTestSuite : public TestSuite
{
public:
  YoungdsrTestSuite () : TestSuite ("routing-youngdsr", UNIT)
  {
    AddTestCase (new YoungdsrFsHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrRreqHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrRrepHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrSRHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrRerrHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrAckReqHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrAckHeaderTest, TestCase::QUICK);
    AddTestCase (new YoungdsrCacheEntryTest, TestCase::QUICK);
    AddTestCase (new YoungdsrSendBuffTest, TestCase::QUICK);
  }
} g_youngdsrTestSuite;
