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

// UserRequestPreferences UserRequestPreferences
// swagger:model UserRequestPreferences
type UserRequestPreferences struct {

	// The currency of the user. This currency will be respected while providing the response for derived API services.<br><b>Applicable Values</b><br>
	// * AUD: Australia Dollar<br>
	// * BRL: Brazil Real<br>
	// * CAD: Canada Dollar<br>
	// * EUR: Euro Member Countries<br>
	// * GBP: United Kingdom Pound<br>
	// * HKD: Hong Kong Dollar<br>
	// * IDR: Indonesia Rupiah<br>
	// * INR: India Rupee<br>
	// * JPY: Japan Yen<br>
	// * NZD: New Zealand Dollar<br>
	// * SGD: Singapore Dollar<br>
	// * USD: United States Dollar<br>
	// * ZAR: South Africa Rand<br>
	// * CNY: China Yuan Renminbi<br>
	// * VND: Viet Nam Dong<br>
	// Enum: [AUD BRL CAD EUR GBP HKD IDR INR JPY NZD SGD USD ZAR CNY VND]
	Currency string `json:"currency,omitempty"`

	// The locale of the user. This locale will be considered for localization features like providing the provider information in the supported locale or providing category names in the transaction related services.<br><b>Applicable Values</b><br>
	// * en_US: English - United States of America<br>
	// * en_ES: Spanish - Spain<br>
	// * fr_CA: French - Canada<br>
	// * zh_CN: Chinese - China<br>
	// Enum: [en_US en_ES fr_CA zh_CN]
	Locale string `json:"locale,omitempty"`
}

// Validate validates this user request preferences
func (m *UserRequestPreferences) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCurrency(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocale(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var userRequestPreferencesTypeCurrencyPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["AUD","BRL","CAD","EUR","GBP","HKD","IDR","INR","JPY","NZD","SGD","USD","ZAR","CNY","VND"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userRequestPreferencesTypeCurrencyPropEnum = append(userRequestPreferencesTypeCurrencyPropEnum, v)
	}
}

const (

	// UserRequestPreferencesCurrencyAUD captures enum value "AUD"
	UserRequestPreferencesCurrencyAUD string = "AUD"

	// UserRequestPreferencesCurrencyBRL captures enum value "BRL"
	UserRequestPreferencesCurrencyBRL string = "BRL"

	// UserRequestPreferencesCurrencyCAD captures enum value "CAD"
	UserRequestPreferencesCurrencyCAD string = "CAD"

	// UserRequestPreferencesCurrencyEUR captures enum value "EUR"
	UserRequestPreferencesCurrencyEUR string = "EUR"

	// UserRequestPreferencesCurrencyGBP captures enum value "GBP"
	UserRequestPreferencesCurrencyGBP string = "GBP"

	// UserRequestPreferencesCurrencyHKD captures enum value "HKD"
	UserRequestPreferencesCurrencyHKD string = "HKD"

	// UserRequestPreferencesCurrencyIDR captures enum value "IDR"
	UserRequestPreferencesCurrencyIDR string = "IDR"

	// UserRequestPreferencesCurrencyINR captures enum value "INR"
	UserRequestPreferencesCurrencyINR string = "INR"

	// UserRequestPreferencesCurrencyJPY captures enum value "JPY"
	UserRequestPreferencesCurrencyJPY string = "JPY"

	// UserRequestPreferencesCurrencyNZD captures enum value "NZD"
	UserRequestPreferencesCurrencyNZD string = "NZD"

	// UserRequestPreferencesCurrencySGD captures enum value "SGD"
	UserRequestPreferencesCurrencySGD string = "SGD"

	// UserRequestPreferencesCurrencyUSD captures enum value "USD"
	UserRequestPreferencesCurrencyUSD string = "USD"

	// UserRequestPreferencesCurrencyZAR captures enum value "ZAR"
	UserRequestPreferencesCurrencyZAR string = "ZAR"

	// UserRequestPreferencesCurrencyCNY captures enum value "CNY"
	UserRequestPreferencesCurrencyCNY string = "CNY"

	// UserRequestPreferencesCurrencyVND captures enum value "VND"
	UserRequestPreferencesCurrencyVND string = "VND"
)

// prop value enum
func (m *UserRequestPreferences) validateCurrencyEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, userRequestPreferencesTypeCurrencyPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *UserRequestPreferences) validateCurrency(formats strfmt.Registry) error {

	if swag.IsZero(m.Currency) { // not required
		return nil
	}

	// value enum
	if err := m.validateCurrencyEnum("currency", "body", m.Currency); err != nil {
		return err
	}

	return nil
}

var userRequestPreferencesTypeLocalePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["en_US","en_ES","fr_CA","zh_CN"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userRequestPreferencesTypeLocalePropEnum = append(userRequestPreferencesTypeLocalePropEnum, v)
	}
}

const (

	// UserRequestPreferencesLocaleEnUS captures enum value "en_US"
	UserRequestPreferencesLocaleEnUS string = "en_US"

	// UserRequestPreferencesLocaleEnES captures enum value "en_ES"
	UserRequestPreferencesLocaleEnES string = "en_ES"

	// UserRequestPreferencesLocaleFrCA captures enum value "fr_CA"
	UserRequestPreferencesLocaleFrCA string = "fr_CA"

	// UserRequestPreferencesLocaleZhCN captures enum value "zh_CN"
	UserRequestPreferencesLocaleZhCN string = "zh_CN"
)

// prop value enum
func (m *UserRequestPreferences) validateLocaleEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, userRequestPreferencesTypeLocalePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *UserRequestPreferences) validateLocale(formats strfmt.Registry) error {

	if swag.IsZero(m.Locale) { // not required
		return nil
	}

	// value enum
	if err := m.validateLocaleEnum("locale", "body", m.Locale); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserRequestPreferences) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserRequestPreferences) UnmarshalBinary(b []byte) error {
	var res UserRequestPreferences
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}