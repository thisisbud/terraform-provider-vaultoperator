package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/url"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const (
	argSecretShares    = "secret_shares"
	argSecretThreshold = "secret_threshold"
	argRootToken       = "root_token"
	argKeys            = "keys"
	argKeysBase64      = "keys_base64"
)

func resourceInit() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Resource for vault operator init",

		CreateContext: resourceInitCreate,
		ReadContext:   resourceInitRead,
		UpdateContext: resourceInitUpdate,
		DeleteContext: resourceInitDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceInitImporter,
		},

		Schema: map[string]*schema.Schema{
			argSecretShares: {
				Description: "Specifies the number of shares to split the master key into.",
				Type:        schema.TypeInt,
				Required:    true,
			},
			argSecretThreshold: {
				Description: "Specifies the number of shares required to reconstruct the master key.",
				Type:        schema.TypeInt,
				Required:    true,
			},
			argRootToken: {
				Description: "The Vault Root Token.",
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
			},
			argKeys: {
				Description: "The unseal keys.",
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argKeysBase64: {
				Description: "The unseal keys, base64 encoded.",
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceInitCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)

	req := api.InitRequest{
		SecretShares:    d.Get(argSecretShares).(int),
		SecretThreshold: d.Get(argSecretThreshold).(int),
	}

	res, err := client.client.Sys().Init(&req)

	if err != nil {
		logError("failed to initialize Vault: %v", err)
		return diag.FromErr(err)
	}

	updateState(d, client.client.Address(), res)

	return diag.Diagnostics{}
}

func resourceInitRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Errorf("not implemented")
}

func resourceInitUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Errorf("not implemented")
}

func resourceInitDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Errorf("not implemented")
}

func resourceInitImporter(c context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	client := meta.(*apiClient)
	// Id should be a file scheme URL: file://path_to_file.json
	// The json file schema should be the same as what's returned from the sys/init API (i.e. a InitResponse)
	id := d.Id()

	u, err := url.Parse(id)
	if err != nil {
		logError("failed parsing id url %v", err)
		return nil, err
	}

	if u.Scheme != "file" {
		logError("unsupported scheme")
		return nil, errors.New("unsupported scheme")
	}

	fc, err := ioutil.ReadFile(filepath.Join(u.Host, u.Path))

	if err != nil {
		logError("failed reading file %v", err)
		return nil, err
	}

	var initResponse api.InitResponse
	if err := json.Unmarshal(fc, &initResponse); err != nil {
		logError("failed unmarshalling json: %v", err)
		return nil, err
	}

	updateState(d, client.client.Address(), &initResponse)
	return []*schema.ResourceData{d}, nil
}

func updateState(d *schema.ResourceData, id string, res *api.InitResponse) {
	d.SetId(id)
	d.Set(argRootToken, res.RootToken)
	d.Set(argKeys, res.Keys)
	d.Set(argKeysBase64, res.KeysB64)
}