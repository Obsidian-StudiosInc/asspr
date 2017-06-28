/****************************************************************************
 *  version.h
 *  Anti-Spam Server Proxy Report
 *  Copyright 2016 Obsidian-Studios, Inc.
 *  Author William L. Thomson Jr.
 *         wlt@obsidian-studios.com
 ****************************************************************************/

/*
 *  This file is part of asspr.
 *
 *  ASSPR_ is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ASSPR_ is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ASSPR_.  If not, see <http://www.gnu.org/licenses/>.
 */

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define ASSPR_CONTACT "Obsidian-Studios, Inc. <support@obsidian-studios.com>"
#define ASSPR_VERSION_MAJOR 0
#define ASSPR_VERSION_MINOR 2
#define ASSPR_VERSION_PATCH 8
#define ASSPR_VERSION_SEPARATOR "."
#define ASSPR_VERSION_NUMERIC STR(ASSPR_VERSION_MAJOR) "." STR(ASSPR_VERSION_MINOR) "." STR(ASSPR_VERSION_PATCH)
#define ASSPR_VERSION_STR "asspr, v" ASSPR_VERSION_NUMERIC
