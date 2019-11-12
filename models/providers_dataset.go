// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ProvidersDataset ProvidersDataset
// swagger:model ProvidersDataset
type ProvidersDataset struct {

	// The name of the dataset attribute suported by the provider.<br><br><b>Endpoints</b>:<ul><li>GET providers/{providerId}</li><li>GET providers</li></ul>
	Attribute []*Attribute `json:"attribute"`

	// The name of the dataset requested from the provider site<br><br><b>Account Type</b>: Manual<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li><li>GET providerAccounts</li><li>POST providerAccounts</li><li>PUT providerAccounts/{providerAccountId}</li><li>GET providerAccounts/{providerAccountId}</li><li>GET providers/{providerId}</li><li>GET providers</li></ul><b>Applicable Values</b><br>
	// * BASIC_AGG_DATA: Indicates basic aggregation data like accounts, transactions, etc.<br>
	// * ADVANCE_AGG_DATA: Indicates advance aggregation data like interest details and payment details.<br>
	// * ACCT_PROFILE: Indicates account profile datas like full account number, routing number, etc.<br>
	// * DOCUMENT: Indicates document data like bank statements, tax documents, etc.<br>
	// Enum: [BASIC_AGG_DATA ADVANCE_AGG_DATA ACCT_PROFILE DOCUMENT]
	Name string `json:"name,omitempty"`
}

// Validate validates this providers dataset
func (m *ProvidersDataset) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttribute(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProvidersDataset) validateAttribute(formats strfmt.Registry) error {

	if swag.IsZero(m.Attribute) { // not required
		return nil
	}

	for i := 0; i < len(m.Attribute); i++ {
		if swag.IsZero(m.Attribute[i]) { // not required
			continue
		}

		if m.Attribute[i] != nil {
			if err := m.Attribute[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attribute" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var providersDatasetTypeNamePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BASIC_AGG_DATA","ADVANCE_AGG_DATA","ACCT_PROFILE","DOCUMENT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		providersDatasetTypeNamePropEnum = append(providersDatasetTypeNamePropEnum, v)
	}
}

const (

	// ProvidersDatasetNameBASICAGGDATA captures enum value "BASIC_AGG_DATA"
	ProvidersDatasetNameBASICAGGDATA string = "BASIC_AGG_DATA"

	// ProvidersDatasetNameADVANCEAGGDATA captures enum value "ADVANCE_AGG_DATA"
	ProvidersDatasetNameADVANCEAGGDATA string = "ADVANCE_AGG_DATA"

	// ProvidersDatasetNameACCTPROFILE captures enum value "ACCT_PROFILE"
	ProvidersDatasetNameACCTPROFILE string = "ACCT_PROFILE"

	// ProvidersDatasetNameDOCUMENT captures enum value "DOCUMENT"
	ProvidersDatasetNameDOCUMENT string = "DOCUMENT"
)

// prop value enum
func (m *ProvidersDataset) validateNameEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, providersDatasetTypeNamePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *ProvidersDataset) validateName(formats strfmt.Registry) error {

	if swag.IsZero(m.Name) { // not required
		return nil
	}

	// value enum
	if err := m.validateNameEnum("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ProvidersDataset) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProvidersDataset) UnmarshalBinary(b []byte) error {
	var res ProvidersDataset
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}