/*
 * Copyright (C) 2007-2018 Siemens AG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************************
 *
 * @author Daniel.Peintner.EXT@siemens.com
 * @author Sebastian.Kaebisch@siemens.com
 * @version 0.9.4
 * @contact Richard.Kuntschke@siemens.com
 *
 *
 ********************************************************************/

#include "EVSE.h"
#define CERT_FILE "/home/ohm/entity.crt"
#define KEY_FILE "/home/ohm/entity.key"
#define PORT_NUMBER 11125

int main_example(int argc, char *argv[]) {
	// Call server_tls with appropriate arguments
	server_tls(CERT_FILE, KEY_FILE, PORT_NUMBER);
}