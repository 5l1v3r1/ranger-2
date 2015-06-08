// This piece of sh^Wcode has been ported from PHP.
// You can find original version here: 
//   https://github.com/pfsense/pfsense/blob/master/etc/inc/util.inc
//
// Also, I don't know anything about error handling in Go.

package ranger

import (
	"strings"
	"strconv"
	"bytes"
	"fmt"
)

type CIDR struct {
	ip   uint32
	mask uint8
}

type rangeError struct {
	msg string
}

func (err rangeError) Error() string {
	return err.msg
}

type ipConvError struct {
	msg string
}

func (err ipConvError) Error() string {
	return err.msg
}

type formatError struct {
	msg	 string
}

func (err formatError) Error() string {
	return err.msg
}

func (cidr *CIDR) String() string {
	if (cidr.mask == 32){
		return intToIP(cidr.ip)
	} else {
		return fmt.Sprintf("%s/%d", intToIP(cidr.ip), cidr.mask)
	}
}

func ipToInt(ip string) (int_ip uint32, err error) {
	octets := strings.Split(ip, ".")

	if (len(octets) != 4) {
		return 0, ipConvError{"Wrong IP format"}
	} else {
		for x, octet := range octets {
			value, err := strconv.Atoi(octet)
			if (err != nil || value > 255 || value < 0) {
				return 0, ipConvError{"Wrong IP value"}
			}

			int_ip |= (uint32)(value << (uint)(24 - 8 * x))
		}

		return int_ip, nil
	}
}

func intToIP(int_ip uint32) (ip string) {
	var buffer bytes.Buffer

	for x := 0; x < 4; x++ {
		shift := (uint)(24 - 8 * x)
		octet := int_ip & (0xFF << shift) >> shift

		buffer.WriteString(strconv.Itoa((int)(octet)))

		if (x != 3) {
			buffer.WriteString(".")
		}
	}

	return buffer.String()
}

func rangeSize(start uint32, end uint32) (size int) {
	return (int)(end - start + 1)
}

func smallestCIDR(size int) (smallest uint8) {
	smallest = 1

	for i := (uint8)(32); i > 1; i-- {
		if (size <= (2 << (i - 1))) {
			smallest = i
		}
	}
		
	return 32 - smallest
}

func subnetMask(bits uint8) (mask uint32) {
	mask = 0

	for i := (uint8)(0); i < bits; i++ {
		mask >>= 1
		mask |= 0x80000000
	}

	return mask
}

func genSubnet(ip uint32, bits uint8) (subnet uint32) {
	return ip & subnetMask(bits)
}

func subnetMax(ip uint32, bits uint8) (max uint32) {
	return ip | ^subnetMask(bits)
}

// WE NEED SOME REFACTORING HERE
// HERP DERP DERP
func rangeSubnets(block_start uint32, block_end uint32) (subnets []CIDR) {
	cidr := smallestCIDR(rangeSize(block_start, block_end))

	for ; cidr <= 32; cidr++ {
		sub_min := genSubnet(block_start, cidr)
		sub_max := subnetMax(block_start, cidr)

		if ((sub_min == block_start) && (sub_max == block_end)) {
			return []CIDR{CIDR{block_start, cidr}}
		}

		if ((sub_min >= block_start) && (sub_max <= block_end)) {
			break
			}
	}

	sub_min := genSubnet(block_start, cidr)
	sub_max := subnetMax(block_start, cidr)

	// Some logic that will recursivly search from block_start to the first IP before
	// the start of the subnet we just found.
	// NOTE: This may never be hit, the way the above algo turned out, but is left
	// for completeness.
	if (block_start != sub_min) {
		subnets = append(subnets, rangeSubnets(block_start, block_end - 1)...)
	}

	// Add in the subnet we found before, to preserve ordering
	subnets = append(subnets, CIDR{sub_min, cidr})

	// And some more logic that will search after the subnet we found to fill in
	// to the end of the range.
	if (block_end != sub_max) {
		subnets = append(subnets, rangeSubnets(sub_max + 1, block_end)...)
	}

	return subnets
}

func Parse(line string) (subnets []CIDR, err error) {
	line = strings.Replace(line, " ", "", -1)
				
	lr := strings.Split(line, "-")
	if (len(lr) > 2) {

		//
		// Possibly stupid NMAP range format. Just ignore it.
		//

		return nil, formatError{"There's no NMAP ranges support yet"}
	} else if (len(lr) == 1) {
				
		//
		// One signle IP (a.a.a.a) or CIDR (a.a.a.a/z)
		//

		parts := strings.Split(lr[0], "/")

		if (len(parts) == 2) {

			//
			// Trying to read as a CIDR
			//

			ip, err := ipToInt(parts[0])
			if (err != nil) {
				return nil, formatError{"Wrong IP format"}
			}

			subnet, err := strconv.Atoi(parts[1])
			if (err != nil || subnet < 0 || subnet > 32) {
				return nil, formatError{"Wrong subnet mask"}
			}

			return []CIDR{CIDR{ip, (uint8)(subnet)}}, nil
		} else if (len(parts) == 1) {
						
			//
			// Trying to read as an IP address
			//
						
			ip, err := ipToInt(lr[0])
			if (err != nil) {
				return nil, formatError{"Wrong IP format"}
			}

			return []CIDR{CIDR{ip, 32}}, nil
		} else {
						
			//
			// Whoooa, too much slashes
			//
						
			return nil, formatError{"Wrong IP format"}
		}
	} else {

		//
		// IP block range (a.a.a.a-b.b.b.b)
		//

		block_start, err := ipToInt(lr[0])
		if (err != nil) {
			return nil, formatError{"Wrong IP format"}
		}

		block_end, err := ipToInt(lr[1])
		if (err != nil) {
			return nil, formatError{"Wrong IP format"}
		}

		if (block_start > block_end) {
			return nil, formatError{"IP block start can't be greater than IP block end"}
		}

		return rangeSubnets(block_start, block_end), nil
	}
}