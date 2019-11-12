// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Identifier Identifier
// swagger:model Identifier
type Identifier struct {

	// Type of Identifier
	// Read Only: true
	// Enum: [NIE DNI EIN BN AADHAR NIN NRIC]
	Type string `json:"type,omitempty"`

	// Value of the identifier
	// Read Only: true
	Value string `json:"value,omitempty"`
}

// Validate validates this identifier
func (m *Identifier) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var identifierTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["NIE","DNI","EIN","BN","AADHAR","NIN","NRIC"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		identifierTypeTypePropEnum = append(identifierTypeTypePropEnum, v)
	}
}

const (

	// IdentifierTypeNIE captures enum value "NIE"
	IdentifierTypeNIE string = "NIE"

	// IdentifierTypeDNI captures enum value "DNI"
	IdentifierTypeDNI string = "DNI"

	// IdentifierTypeEIN captures enum value "EIN"
	IdentifierTypeEIN string = "EIN"

	// IdentifierTypeBN captures enum value "BN"
	IdentifierTypeBN string = "BN"

	// IdentifierTypeAADHAR captures enum value "AADHAR"
	IdentifierTypeAADHAR string = "AADHAR"

	// IdentifierTypeNIN captures enum value "NIN"
	IdentifierTypeNIN string = "NIN"

	// IdentifierTypeNRIC captures enum value "NRIC"
	IdentifierTypeNRIC string = "NRIC"
)

// prop value enum
func (m *Identifier) validateTypeEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, identifierTypeTypePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Identifier) validateType(formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Identifier) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Identifier) UnmarshalBinary(b []byte) error {
	var res Identifier
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}