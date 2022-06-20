package provider

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
	"strings"
)

const (
	envVaultAddr      = "VAULT_ADDR"
	provider          = "vaultoperator"
	resInit           = provider + "_init"
	argVaultUrl       = "vault_url"
	argVaultAddr      = "vault_addr"
	argRequestHeaders = "request_headers"
	argKubeConfig     = "kube_config"
	argKubeConfigPath = "path"
	argNameSpace      = "namespace"
	argServiceName    = "service"
	argLocalPort      = "local_port"
	argRemotePort     = "remote_port"
	argUseTLS         = "use_tls"
	argCaCert         = "ca_cert"
	argClientCert     = "client_cert"
	argClientKey      = "client_key"
	argInsecureTLS    = "use_insecure_tls"
)

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	// Customize the content of descriptions when output. For example you can add defaults on
	// to the exported descriptions if present.
	// schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
	// 	desc := s.Description
	// 	if s.Default != nil {
	// 		desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
	// 	}
	// 	return strings.TrimSpace(desc)
	// }
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: providerSchema(),
			ResourcesMap: map[string]*schema.Resource{
				resInit: resourceInit(),
			},
			DataSourcesMap: map[string]*schema.Resource{
				resInit: providerDatasource(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type kubeConn struct {
	configPath  string
	nameSpace   string
	serviceName string
	localPort   string
	remotePort  string
	kubeConfig  *rest.Config
	kubeClient  *kubernetes.Clientset
}

type tlsConfig struct {
	caCert     string
	clientCert string
	clientKey  string
	insecure   bool
}

type apiClient struct {
	// Add whatever fields, client or connection info, etc. here
	// you would need to setup to communicate with the upstream
	// API.
	client    *api.Client
	url       string
	kubeConn  kubeConn
	tlsAdded  bool
	tlsConfig tlsConfig
}

func providerSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		argVaultUrl: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Vault instance URL",
			Deprecated:  fmt.Sprintf("%q is deprecated, please use %q instead", argVaultUrl, argVaultAddr),
		},
		argVaultAddr: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Vault instance URL",
		},
		argRequestHeaders: {
			Type:     schema.TypeMap,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		argKubeConfig: {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					argKubeConfigPath: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Full path to a Kubernetes config",
						Default:     "~/.kube/config",
					},
					argNameSpace: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Kubernetes namespace where HC Vault is run",
					},
					argServiceName: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Kubernetes service name of Vault",
					},
					argLocalPort: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Local forward port",
						Default:     "8200",
					},
					argRemotePort: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Remote service port to forward",
						Default:     "8200",
					},
					argUseTLS: {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Use TLS when proxying via kubectl proxy",
						Default:     false,
					},
					argCaCert: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "CA to use when proxying via kubectl proxy",
						Default:     false,
					},
					argClientCert: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Client Cert to use when proxying via kubectl proxy",
						Default:     false,
					},
					argClientKey: {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Client Key to use when proxying via kubectl proxy",
						Default:     false,
					},
					argInsecureTLS: {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Validate the TLS connection between the provider and vault",
						Default:     true,
					},
				},
			},
		},
	}
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		a := &apiClient{}

		if k := d.Get(argKubeConfig).([]interface{}); len(k) > 0 {
			kubeConn := k[0].(map[string]interface{})

			path := kubeConn[argKubeConfigPath].(string)

			if strings.Contains(path, "~") {
				homeDir, err := homeDir()
				if err != nil {
					return nil, diag.FromErr(err)
				}
				path = strings.Replace(path, "~", homeDir, -1)
			}

			// Create Kubernetes *rest.Config
			kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
			if err != nil {
				return nil, diag.FromErr(err)
			}
			a.kubeConn.kubeConfig = kubeConfig

			// Create Kubernetes *kubernetes.Clientset
			kubeClient, err := kubernetes.NewForConfig(a.kubeConn.kubeConfig)
			if err != nil {
				return nil, diag.FromErr(err)
			}
			a.kubeConn.kubeClient = kubeClient

			if namespace := kubeConn[argNameSpace].(string); namespace != "" {
				a.kubeConn.nameSpace = namespace
			} else {
				return nil, diag.Errorf("Vault namespace is not specified")
			}

			if service := kubeConn[argServiceName].(string); service != "" {
				a.kubeConn.serviceName = service
			} else {
				return nil, diag.Errorf("Vault service name is not specified")
			}

			a.kubeConn.localPort = kubeConn[argLocalPort].(string)
			a.kubeConn.remotePort = kubeConn[argRemotePort].(string)
			if kubeConn[argUseTLS].(bool) {
				a.url = fmt.Sprintf("https://localhost:%s", a.kubeConn.localPort)
				a.tlsConfig = tlsConfig{caCert: "", clientCert: "", clientKey: "", insecure: false}
				a.tlsAdded = true
			} else {
				a.url = fmt.Sprintf("http://localhost:%s", a.kubeConn.localPort)
				a.tlsAdded = false
			}
		} else {
			if u := d.Get(argVaultAddr).(string); u != "" {
				a.url = u
				a.tlsAdded = false
			} else if u := d.Get(argVaultUrl).(string); u != "" {
				a.url = u
				a.tlsAdded = false
			} else {
				a.url = os.Getenv(envVaultAddr)
				a.tlsAdded = false
			}
		}

		if a.url == "" {
			return nil, diag.Errorf("argument '%s' is required, or set VAULT_ADDR environment variable", argVaultUrl)
		}

		var vaultConfig = api.Config{Address: a.url}
		if a.tlsAdded {
			err := vaultConfig.ConfigureTLS(&api.TLSConfig{
				CACert:     a.tlsConfig.caCert,
				ClientCert: a.tlsConfig.clientCert,
				ClientKey:  a.tlsConfig.clientKey,
				Insecure:   a.tlsConfig.insecure,
			})
			if err != nil {
				logError("failed to configure Vault API client with TLS: %v", err)
				return nil, diag.FromErr(err)
			}
		}

		if c, err := api.NewClient(&vaultConfig); err != nil {
			logError("failed to create Vault API client: %v", err)
			return nil, diag.FromErr(err)
		} else {
			a.client = c
		}

		return a, nil
	}
}

func logError(fmt string, v ...interface{}) {
	log.Printf("[ERROR] "+fmt, v)
}

func logInfo(fmt string, v ...interface{}) {
	log.Printf("[INFO] "+fmt, v)
}

func logDebug(fmt string, v ...interface{}) {
	log.Printf("[DEBUG] "+fmt, v)
}

func homeDir() (string, error) {
	if h := os.Getenv("HOME"); h != "" {
		return h, nil
	}
	return "", fmt.Errorf("unable to get HOME directory")
}
