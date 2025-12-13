# -*- coding: UTF-8 -*-
from .__common__ import Web


__all__ = ["VxUnderground"]


class VxUnderground(Web):
    url = "https://vx-underground.org/Samples"
    
    def get_malware_feed(self):
        #TODO
        pass

