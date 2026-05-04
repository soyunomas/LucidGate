package proxy

import (
	"fmt"
	"net"
	"net/netip"
)

type AccessProfile struct {
	Name    string
	Clients []string
	Default bool
}

type AccessRules struct {
	entries        []accessEntry
	defaultProfile string
}

type accessEntry struct {
	prefix  netip.Prefix
	profile string
}

func NewAccessRules(profiles []AccessProfile) (*AccessRules, error) {
	rules := &AccessRules{}
	if len(profiles) == 0 {
		rules.defaultProfile = "default"
		return rules, nil
	}
	for _, profile := range profiles {
		if profile.Name == "" {
			return nil, fmt.Errorf("access profile name cannot be empty")
		}
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
			rules.entries = append(rules.entries, accessEntry{
				prefix:  prefix.Masked(),
				profile: profile.Name,
			})
		}
	}
	return rules, nil
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
	for _, entry := range r.entries {
		if entry.prefix.Contains(addr) {
			return entry.profile, true
		}
	}
	if r.defaultProfile != "" {
		return r.defaultProfile, true
	}
	return "", false
}
