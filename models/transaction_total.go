// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// TransactionTotal TransactionTotal
// swagger:model TransactionTotal
type TransactionTotal struct {

	// count
	Count int64 `json:"count,omitempty"`
}

// Validate validates this transaction total
func (m *TransactionTotal) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TransactionTotal) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransactionTotal) UnmarshalBinary(b []byte) error {
	var res TransactionTotal
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
