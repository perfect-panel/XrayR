package ppanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

type APIClient struct {
	client   *resty.Client
	APIHost  string
	ServerID int
	Secret   string
	Protocol string
	eTags    map[string]string
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"server_id":  strconv.Itoa(apiConfig.NodeID),
		"protocol":   strings.ToLower(apiConfig.NodeType),
		"secret_key": apiConfig.Key,
	})
	return &APIClient{
		client:   client,
		APIHost:  apiConfig.APIHost,
		ServerID: apiConfig.NodeID,
		Secret:   apiConfig.Key,
		Protocol: apiConfig.NodeType,
		eTags:    make(map[string]string),
	}
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.ServerID, Key: c.Secret, NodeType: c.Protocol}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

// assembleURL assemble the URL
func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

// GetNodeInfo get the node info
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	config := GetServerConfigResponse{}
	path := "/v1/server/config"
	resp, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		SetResult(&config).Get(path)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err)
	}
	if resp.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	var b []byte
	if b, err = config.Config.MarshalJSON(); err != nil {
		return nil, err
	}
	c.eTags["node"] = resp.Header().Get("ETag")
	// parse Protocol
	switch config.Protocol {
	case "shadowsocks":

		var shadowsocksConfig Shadowsocks
		if err := json.Unmarshal(b, &shadowsocksConfig); err != nil {
			return nil, err
		}
		return c.parseShadowsocksConfig(&shadowsocksConfig)
	case "vless":

		var vlessConfig Vless
		if err := json.Unmarshal(b, &vlessConfig); err != nil {
			return nil, err
		}

		return c.parseVlessConfig(&vlessConfig)
	case "vmess":
		var vmessConfig Vmess
		if err := json.Unmarshal(b, &vmessConfig); err != nil {

			return nil, err
		}
		return c.parseVmessConfig(&vmessConfig)
	case "trojan":
		var trojanConfig Trojan
		if err := json.Unmarshal(b, &trojanConfig); err != nil {
			return nil, err
		}
		return c.parseTrojanConfig(&trojanConfig)
	default:
		msg := fmt.Sprintf("invalid protocol: %v", config.Protocol)
		return nil, errors.New(msg)
	}
}

// parse shadowsocks config
func (c *APIClient) parseShadowsocksConfig(config *Shadowsocks) (*api.NodeInfo, error) {
	if config == nil {
		return nil, fmt.Errorf("shadowsocks config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}
	return &api.NodeInfo{
		NodeType:          "Shadowsocks",
		TransportProtocol: "tcp",
		NodeID:            c.ServerID,
		Port:              uint32(config.Port),
		CypherMethod:      config.Method,
	}, nil
}

// parse vless config
func (c *APIClient) parseVlessConfig(config *Vless) (*api.NodeInfo, error) {
	var (
		header        json.RawMessage
		enableTLS     bool
		enableReality bool
		dest          string
	)

	if config == nil {
		return nil, fmt.Errorf("vmess config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}

	if config.SecurityConfig.SNI != "" {
		dest = config.SecurityConfig.SNI
	}
	realityConfig := api.REALITYConfig{
		Dest:             dest + ":" + strconv.Itoa(config.Port),
		ProxyProtocolVer: 0,
		ServerNames: []string{
			config.SecurityConfig.SNI,
		},
		PrivateKey: config.SecurityConfig.RealityPrivateKey,
		ShortIds: []string{
			config.SecurityConfig.RealityShortId,
		},
	}
	switch config.Security {
	case "none":
		enableTLS = false
		enableReality = false

	case "tls":
		enableTLS = true
		enableReality = false

	case "reality":
		enableTLS = true
		enableReality = true
	}
	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "V2ray",
		Port:              uint32(config.Port),
		Host:              config.TransportConfig.Host,
		Path:              config.TransportConfig.Path,
		AlterID:           0,
		Header:            header,
		ServiceName:       config.TransportConfig.ServiceName,
		TransportProtocol: config.Transport,
		EnableTLS:         enableTLS,
		EnableREALITY:     enableReality,
		REALITYConfig:     &realityConfig,
		VlessFlow:         config.Flow,
	}, nil
}

// parse vmess config
func (c *APIClient) parseVmessConfig(config *Vmess) (*api.NodeInfo, error) {
	if config == nil {
		return nil, fmt.Errorf("vmess config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}

	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "V2ray",
		Port:              uint32(config.Port),
		Host:              config.TransportConfig.Host,
		Path:              config.TransportConfig.Path,
		AlterID:           0,
		ServiceName:       config.SecurityConfig.SNI,
		EnableTLS:         config.Security == "tls",
		TransportProtocol: config.Transport,
	}, nil
}

// parse trojan config
func (c *APIClient) parseTrojanConfig(config *Trojan) (*api.NodeInfo, error) {
	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "Trojan",
		Port:              uint32(config.Port),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              config.TransportConfig.Host,
		ServiceName:       config.SecurityConfig.SNI,
	}, nil
}

func (c *APIClient) GetUserList() (userList *[]api.UserInfo, err error) {
	result := GetServerUserListResponse{}
	path := "/v1/server/user"
	resp, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["user"]).
		ForceContentType("application/json").
		SetResult(&result).Get(path)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	if resp.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	c.eTags["user"] = resp.Header().Get("ETag")
	users := make([]api.UserInfo, 0)
	for _, user := range result.Users {
		u := api.UserInfo{
			UID:         int(user.Id),
			UUID:        user.UUID,
			SpeedLimit:  uint64(user.SpeedLimit * 1000000 / 8),
			DeviceLimit: int(user.DeviceLimit),
			Email:       user.UUID + "@ppanel.dev",
		}
		if c.Protocol == "Shadowsocks" {
			u.Passwd = user.UUID
		}
		users = append(users, u)
	}
	return &users, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := "/v1/server/status"
	status := ServerPushStatusRequest{
		Cpu:       nodeStatus.CPU,
		Mem:       nodeStatus.Mem,
		Disk:      nodeStatus.Disk,
		UpdatedAt: time.Now().UnixMilli(),
	}
	if _, err = c.client.R().SetBody(status).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUser *[]api.OnlineUser) (err error) {
	path := "/v1/server/online"
	users := make([]OnlineUser, 0)
	for _, u := range *onlineUser {
		users = append(users, OnlineUser{
			UID: int64(u.UID),
			IP:  u.IP,
		})
	}
	if _, err = c.client.R().SetBody(users).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) (err error) {
	path := "/v1/server/push"
	traffic := make([]UserTraffic, 0)
	for _, t := range *userTraffic {
		traffic = append(traffic, UserTraffic{
			UID:      int64(t.UID),
			Upload:   t.Upload,
			Download: t.Download,
		})
	}
	req := ServerPushUserTrafficRequest{
		Traffic: traffic,
	}
	if _, err = c.client.R().SetBody(req).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}

func (c *APIClient) GetNodeRule() (ruleList *[]api.DetectRule, err error) {
	list := make([]api.DetectRule, 0)
	return &list, nil
}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}
