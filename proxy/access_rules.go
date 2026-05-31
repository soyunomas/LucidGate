package proxy

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/gaissmai/bart"
)

type AccessProfile struct {
	Name      string
	Clients   []string
	Default   bool
	MaxConns  *int
	RateLimit *float64
	RateBurst *int
}

type AccessRules struct {
	entries        bart.Table[string]
	defaultProfile string
	banned         bart.Table[bool]
	exceptions     bart.Table[bool]
	profiles       map[string]AccessProfile
}

func NewAccessRules(profiles []AccessProfile) (*AccessRules, error) {
	rules := &AccessRules{
		profiles: make(map[string]AccessProfile),
	}
	if len(profiles) == 0 {
		rules.defaultProfile = "default"
		return rules, nil
	}
	for _, profile := range profiles {
		if profile.Name == "" {
			return nil, fmt.Errorf("access profile name cannot be empty")
		}
		rules.profiles[profile.Name] = profile
		if profile.Default {
			if rules.defaultProfile != "" {
				return nil, fmt.Errorf("multiple default access profiles")
			}
			rules.defaultProfile = profile.Name
		}
		for _, client := range profile.Clients {
			prefix, err := netip.ParsePrefix(client)
			if err != nil {
				addr, addrErr := netip.ParseAddr(client)
				if addrErr != nil {
					return nil, fmt.Errorf("access profile %s client %q: %w", profile.Name, client, err)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			rules.entries.Insert(prefix.Masked(), profile.Name)
		}
	}
	return rules, nil
}

func (r *AccessRules) SetBanned(banned []string) error {
	if r == nil {
		return nil
	}
	r.banned = bart.Table[bool]{}
	for _, entry := range banned {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return fmt.Errorf("banned client %q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		r.banned.Insert(prefix.Masked(), true)
	}
	return nil
}

func (r *AccessRules) SetExceptions(exceptions []string) error {
	if r == nil {
		return nil
	}
	r.exceptions = bart.Table[bool]{}
	for _, entry := range exceptions {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return fmt.Errorf("exception client %q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		r.exceptions.Insert(prefix.Masked(), true)
	}
	return nil
}

func (r *AccessRules) ProfileForRemoteAddr(remoteAddr string) (string, bool) {
	if r == nil {
		return "", true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}

	// 1. Check if client IP is explicitly exempted
	if _, excepted := r.exceptions.Lookup(addr); excepted {
		// client is exempted from bans, fallback directly to profiles
	} else {
		// 2. Check if client IP is explicitly banned
		if _, banned := r.banned.Lookup(addr); banned {
			return "", false
		}
	}

	// 3. Fallback to standard access profile evaluation via LPM
	if profile, ok := r.entries.Lookup(addr); ok {
		return profile, true
	}

	if r.defaultProfile != "" {
		return r.defaultProfile, true
	}
	return "", false
}

func (r *AccessRules) ProfileLimits(profileName string) (maxConns *int, rateLimit *float64, rateBurst *int, exists bool) {
	if r == nil || r.profiles == nil {
		return nil, nil, nil, false
	}
	p, ok := r.profiles[profileName]
	if !ok {
		return nil, nil, nil, false
	}
	return p.MaxConns, p.RateLimit, p.RateBurst, true
}
