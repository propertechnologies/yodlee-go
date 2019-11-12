// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// Profile Profile
// swagger:model Profile
type Profile struct {

	// Address available in the profile page of the account.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	Address []*AccountAddress `json:"address"`

	// Email Id available in the profile page of the account.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	Email []*Email `json:"email"`

	// Gender of the provider account holder.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	Gender string `json:"gender,omitempty"`

	// Identifiers available in the profile page of the account.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	Identifier []*Identifier `json:"identifier"`

	// Name of the provider account holder.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	Name []*Name `json:"name"`

	// Phone number available in the profile page of the account.<br><br><b>Aggregated / Manual</b>: Aggregated<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li><li>GET providerAccounts/profile</li></ul>
	// Read Only: true
	PhoneNumber []*PhoneNumber `json:"phoneNumber"`
}

// Validate validates this profile
func (m *Profile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePhoneNumber(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Profile) validateAddress(formats strfmt.Registry) error {

	if swag.IsZero(m.Address) { // not required
		return nil
	}

	for i := 0; i < len(m.Address); i++ {
		if swag.IsZero(m.Address[i]) { // not required
			continue
		}

		if m.Address[i] != nil {
			if err := m.Address[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Profile) validateEmail(formats strfmt.Registry) error {

	if swag.IsZero(m.Email) { // not required
		return nil
	}

	for i := 0; i < len(m.Email); i++ {
		if swag.IsZero(m.Email[i]) { // not required
			continue
		}

		if m.Email[i] != nil {
			if err := m.Email[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("email" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Profile) validateIdentifier(formats strfmt.Registry) error {

	if swag.IsZero(m.Identifier) { // not required
		return nil
	}

	for i := 0; i < len(m.Identifier); i++ {
		if swag.IsZero(m.Identifier[i]) { // not required
			continue
		}

		if m.Identifier[i] != nil {
			if err := m.Identifier[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("identifier" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Profile) validateName(formats strfmt.Registry) error {

	if swag.IsZero(m.Name) { // not required
		return nil
	}

	for i := 0; i < len(m.Name); i++ {
		if swag.IsZero(m.Name[i]) { // not required
			continue
		}

		if m.Name[i] != nil {
			if err := m.Name[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("name" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Profile) validatePhoneNumber(formats strfmt.Registry) error {

	if swag.IsZero(m.PhoneNumber) { // not required
		return nil
	}

	for i := 0; i < len(m.PhoneNumber); i++ {
		if swag.IsZero(m.PhoneNumber[i]) { // not required
			continue
		}

		if m.PhoneNumber[i] != nil {
			if err := m.PhoneNumber[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("phoneNumber" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Profile) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Profile) UnmarshalBinary(b []byte) error {
	var res Profile
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}