// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// NewRegisterUserParams creates a new RegisterUserParams object
// with the default values initialized.
func NewRegisterUserParams() *RegisterUserParams {
	var ()
	return &RegisterUserParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewRegisterUserParamsWithTimeout creates a new RegisterUserParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewRegisterUserParamsWithTimeout(timeout time.Duration) *RegisterUserParams {
	var ()
	return &RegisterUserParams{

		timeout: timeout,
	}
}

// NewRegisterUserParamsWithContext creates a new RegisterUserParams object
// with the default values initialized, and the ability to set a context for a request
func NewRegisterUserParamsWithContext(ctx context.Context) *RegisterUserParams {
	var ()
	return &RegisterUserParams{

		Context: ctx,
	}
}

// NewRegisterUserParamsWithHTTPClient creates a new RegisterUserParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewRegisterUserParamsWithHTTPClient(client *http.Client) *RegisterUserParams {
	var ()
	return &RegisterUserParams{
		HTTPClient: client,
	}
}

/*RegisterUserParams contains all the parameters to send to the API endpoint
for the register user operation typically these are written to a http.Request
*/
type RegisterUserParams struct {

	/*UserRequest
	  userRequest

	*/
	UserRequest *models.UserRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the register user params
func (o *RegisterUserParams) WithTimeout(timeout time.Duration) *RegisterUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the register user params
func (o *RegisterUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the register user params
func (o *RegisterUserParams) WithContext(ctx context.Context) *RegisterUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the register user params
func (o *RegisterUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the register user params
func (o *RegisterUserParams) WithHTTPClient(client *http.Client) *RegisterUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the register user params
func (o *RegisterUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithUserRequest adds the userRequest to the register user params
func (o *RegisterUserParams) WithUserRequest(userRequest *models.UserRequest) *RegisterUserParams {
	o.SetUserRequest(userRequest)
	return o
}

// SetUserRequest adds the userRequest to the register user params
func (o *RegisterUserParams) SetUserRequest(userRequest *models.UserRequest) {
	o.UserRequest = userRequest
}

// WriteToRequest writes these params to a swagger request
func (o *RegisterUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.UserRequest != nil {
		if err := r.SetBodyParam(o.UserRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
