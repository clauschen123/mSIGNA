///////////////////////////////////////////////////////////////////////////////
//
// mSIGNA
//
// docdir.h
//
// Copyright (c) 2013-2014 Eric Lombrozo
// Copyright (c) 2011-2016 Ciphrex Corp.
//
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
//

#pragma once

#include <QString>

const QString& getDocDir();
const QString& getVaultFile();

void setDocDir(const QString& dir);
void setVaultFile(const QString& file);