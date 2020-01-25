#    LibVirt Wake On Lan
#    Copyright (C) 2014 Simon Cadman
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import sys

class Utils(object):

    @staticmethod
    def SetupLogging(logpath=None, logconsole=False, verbose=0):
        returnValue = True
        handlers = []

        if logpath is not None:
            handlers.append(logging.FileHandler(filename=logpath))
        if logconsole:
            handlers.append(logging.StreamHandler(sys.stdout))

        logging.basicConfig(
            level=logging.DEBUG if verbose > 0 else logging.INFO, 
            format='%(levelname)s: %(message)s',
            handlers=handlers
        )

        return returnValue

