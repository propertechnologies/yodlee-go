// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// Coordinates Coordinates
// swagger:model Coordinates
type Coordinates struct {

	// Latitude of the merchant<br><br><b>Applicable containers</b>: bank,creditCard,loan<br>
	Latitude float64 `json:"latitude,omitempty"`

	// Longitude of the merchant<br><br><b>Applicable containers</b>: bank,creditCard,loan<br>
	Longitude float64 `json:"longitude,omitempty"`
}

// Validate validates this coordinates
func (m *Coordinates) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Coordinates) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Coordinates) UnmarshalBinary(b []byte) error {
	var res Coordinates
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}