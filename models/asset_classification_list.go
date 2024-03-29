// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// AssetClassificationList AssetClassificationList
// swagger:model AssetClassificationList
type AssetClassificationList struct {

	// The type of classification to which the investment belongs (assetClass, country, sector, and style).<br><b>Required Feature Enablement</b>: Asset classification feature<br><br><b>Applicable containers</b>: investment<br>
	// Read Only: true
	ClassificationType string `json:"classificationType,omitempty"`

	// The value for each classificationType.<br><b>Required Feature Enablement</b>: Asset classification feature<br><br><b>Applicable containers</b>: investment<br>
	// Read Only: true
	ClassificationValue []string `json:"classificationValue"`
}

// Validate validates this asset classification list
func (m *AssetClassificationList) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AssetClassificationList) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AssetClassificationList) UnmarshalBinary(b []byte) error {
	var res AssetClassificationList
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
