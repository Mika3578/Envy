//
// QueryGGEPHash.h
//
// This file is part of Envy (getenvy.com) © 2016-2018
// Portions copyright Shareaza 2002-2008 and PeerProject 2008-2015
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//
// Envy is distributed in the hope that it will be useful,
// but AS-IS WITHOUT ANY WARRANTY; without even implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License 3.0 for details:
// (http://www.gnu.org/licenses/agpl.html)
//

#pragma once

#include "Hashes.hpp"

class CGGEPItem;

// Shared parser for the GGEP "H" (binary hash) extension used by both G1
// queries (CQuerySearch) and query hits (CQueryHit). Defined in QuerySearch.cpp.
// A zero-length item leaves m_pBuffer NULL, so the type byte is guarded before
// it is dereferenced on a crafted packet. Declared here (rather than ad-hoc in
// each .cpp) so the signature cannot drift between translation units (ODR).
void ReadGGEPHash(const CGGEPItem* pItem, Hashes::Sha1Hash& oSHA1,
	Hashes::TigerHash& oTiger, Hashes::Ed2kHash& oED2K, Hashes::Md5Hash& oMD5);
