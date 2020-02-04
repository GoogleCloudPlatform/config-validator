package asset

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/forseti-security/config-validator/pkg/gcv/configs"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
)

const logRequestsVerboseLevel = 2

func ValidateAsset(asset *validator.Asset) error {
	var result *multierror.Error
	if asset.GetName() == "" {
		result = multierror.Append(result, errors.New("missing asset name"))
	}
	if asset.GetAncestryPath() == "" {
		result = multierror.Append(result, errors.Errorf("asset %q missing ancestry path", asset.GetName()))
	}
	if asset.GetAssetType() == "" {
		result = multierror.Append(result, errors.Errorf("asset %q missing type", asset.GetName()))
	}
	if asset.GetResource() == nil && asset.GetIamPolicy() == nil {
		result = multierror.Append(result, errors.Errorf("asset %q missing both resource and IAM policy", asset.GetName()))
	}
	return result.ErrorOrNil()
}

func ConvertResourceViaJSONToInterface(asset *validator.Asset) (interface{}, error) {
	if asset == nil {
		return nil, nil
	}
	m := &jsonpb.Marshaler{
		OrigName: true,
	}
	if asset.Resource != nil {
		CleanStructValue(asset.Resource.Data)
	}
	glog.V(logRequestsVerboseLevel).Infof("converting asset to golang interface: %v", asset)
	var buf bytes.Buffer
	if err := m.Marshal(&buf, asset); err != nil {
		return nil, errors.Wrapf(err, "marshalling to json with asset %s: %v", asset.Name, asset)
	}
	var f interface{}
	err := json.Unmarshal(buf.Bytes(), &f)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling from json with asset %s: %v", asset.Name, asset)
	}
	return f, nil
}

// SanitizeAncestryPath will populate the AncestryPath field from the ancestors list, or fix the pre-populated one
// if no ancestry list is provided.
func SanitizeAncestryPath(asset *validator.Asset) error {
	if len(asset.Ancestors) != 0 {
		asset.AncestryPath = AncestryPath(asset.Ancestors)
		return nil
	}

	if asset.AncestryPath != "" {
		asset.AncestryPath = configs.NormalizeAncestry(asset.AncestryPath)
		return nil
	}

	return errors.Errorf("no ancestry information for asset %s", asset.String())
}

// AncestryPath returns the ancestry path from a given ancestors list
func AncestryPath(ancestors []string) string {
	cnt := len(ancestors)
	revAncestors := make([]string, len(ancestors))
	for idx := 0; idx < cnt; idx++ {
		revAncestors[cnt-idx-1] = ancestors[idx]
	}
	return strings.Join(revAncestors, "/")
}
