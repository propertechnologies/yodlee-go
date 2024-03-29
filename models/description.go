// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// Description Description
// swagger:model Description
type Description struct {

	// The description of the transaction as defined by the consumer. The consumer can define or provide more details of the transaction in this field.<br><br><b>Applicable containers</b>: bill, creditCard, insurance, loan<br>
	Consumer string `json:"consumer,omitempty"`

	// Original transaction description as it appears at the FI site.<br><br><b>Applicable containers</b>: bill, creditCard, insurance, loan<br>
	// Read Only: true
	Original string `json:"original,omitempty"`

	// The transaction description that appears at the FI site may not be self-explanatory, i.e., the source, purpose of the transaction may not be evident. Yodlee attempts to simplify and make the transaction meaningful to the consumer, and this simplified transaction description is provided in the simple description field.Note: The simple description field is available only in the United States, Canada, United Kingdom, and India.<br><br><b>Applicable containers</b>: bill, creditCard, insurance, loan<br>
	// Read Only: true
	Simple string `json:"simple,omitempty"`
}

// Validate validates this description
func (m *Description) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Description) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Description) UnmarshalBinary(b []byte) error {
	var res Description
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
