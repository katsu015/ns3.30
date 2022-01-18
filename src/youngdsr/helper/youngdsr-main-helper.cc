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

#include "youngdsr-main-helper.h"
#include "ns3/youngdsr-helper.h"
#include "ns3/youngdsr-routing.h"
#include "ns3/youngdsr-rcache.h"
#include "ns3/youngdsr-rreq-table.h"
#include "ns3/node-list.h"
#include "ns3/names.h"
#include "ns3/log.h"
#include "ns3/ptr.h"
#include "ns3/node.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("YoungdsrMainHelper");

YoungdsrMainHelper::YoungdsrMainHelper ()
  : m_youngdsrHelper (0)
{
  NS_LOG_FUNCTION (this);
}

YoungdsrMainHelper::YoungdsrMainHelper (const YoungdsrMainHelper &o)
{
  NS_LOG_FUNCTION (this);
  m_youngdsrHelper = o.m_youngdsrHelper->Copy ();
}

YoungdsrMainHelper::~YoungdsrMainHelper ()
{
  NS_LOG_FUNCTION (this);
  delete m_youngdsrHelper;
}

YoungdsrMainHelper &
YoungdsrMainHelper::operator = (const YoungdsrMainHelper &o)
{
  if (this == &o)
    {
      return *this;
    }
  m_youngdsrHelper = o.m_youngdsrHelper->Copy ();
  return *this;
}

void
YoungdsrMainHelper::Install (YoungdsrHelper &youngdsrHelper, NodeContainer nodes)
{
  NS_LOG_DEBUG ("Passed node container");
  delete m_youngdsrHelper;
  m_youngdsrHelper = youngdsrHelper.Copy ();
  for (NodeContainer::Iterator i = nodes.Begin (); i != nodes.End (); ++i)
    {
      Install (*i);
    }
}

void
YoungdsrMainHelper::Install (Ptr<Node> node)
{
  NS_LOG_FUNCTION (node);
  Ptr<ns3::youngdsr::YoungdsrRouting> youngdsr = m_youngdsrHelper->Create (node);
//  Ptr<ns3::youngdsr::RouteCache> routeCache = CreateObject<ns3::youngdsr::RouteCache> ();
//  Ptr<ns3::youngdsr::RreqTable> rreqTable = CreateObject<ns3::youngdsr::RreqTable> ();
//  youngdsr->SetRouteCache (routeCache);
//  youngdsr->SetRequestTable (rreqTable);
  youngdsr->SetNode (node);
//  node->AggregateObject (routeCache);
//  node->AggregateObject (rreqTable);
}

void
YoungdsrMainHelper::SetYoungdsrHelper (YoungdsrHelper &youngdsrHelper)
{
  NS_LOG_FUNCTION (this);
  delete m_youngdsrHelper;
  m_youngdsrHelper = youngdsrHelper.Copy ();
}

} // namespace ns3
