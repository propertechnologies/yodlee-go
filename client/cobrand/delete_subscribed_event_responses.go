// Code generated by go-swagger; DO NOT EDIT.

package cobrand

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// DeleteSubscribedEventReader is a Reader for the DeleteSubscribedEvent structure.
type DeleteSubscribedEventReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteSubscribedEventReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteSubscribedEventNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteSubscribedEventBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteSubscribedEventUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteSubscribedEventNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteSubscribedEventNoContent creates a DeleteSubscribedEventNoContent with default headers values
func NewDeleteSubscribedEventNoContent() *DeleteSubscribedEventNoContent {
	return &DeleteSubscribedEventNoContent{}
}

/*DeleteSubscribedEventNoContent handles this case with default header values.

OK
*/
type DeleteSubscribedEventNoContent struct {
}

func (o *DeleteSubscribedEventNoContent) Error() string {
	return fmt.Sprintf("[DELETE /cobrand/config/notifications/events/{eventName}][%d] deleteSubscribedEventNoContent ", 204)
}

func (o *DeleteSubscribedEventNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteSubscribedEventBadRequest creates a DeleteSubscribedEventBadRequest with default headers values
func NewDeleteSubscribedEventBadRequest() *DeleteSubscribedEventBadRequest {
	return &DeleteSubscribedEventBadRequest{}
}

/*DeleteSubscribedEventBadRequest handles this case with default header values.

Y803 : eventName required
*/
type DeleteSubscribedEventBadRequest struct {
	Payload *models.YodleeError
}

func (o *DeleteSubscribedEventBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /cobrand/config/notifications/events/{eventName}][%d] deleteSubscribedEventBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteSubscribedEventBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *DeleteSubscribedEventBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSubscribedEventUnauthorized creates a DeleteSubscribedEventUnauthorized with default headers values
func NewDeleteSubscribedEventUnauthorized() *DeleteSubscribedEventUnauthorized {
	return &DeleteSubscribedEventUnauthorized{}
}

/*DeleteSubscribedEventUnauthorized handles this case with default header values.

Unauthorized
*/
type DeleteSubscribedEventUnauthorized struct {
}

func (o *DeleteSubscribedEventUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /cobrand/config/notifications/events/{eventName}][%d] deleteSubscribedEventUnauthorized ", 401)
}

func (o *DeleteSubscribedEventUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteSubscribedEventNotFound creates a DeleteSubscribedEventNotFound with default headers values
func NewDeleteSubscribedEventNotFound() *DeleteSubscribedEventNotFound {
	return &DeleteSubscribedEventNotFound{}
}

/*DeleteSubscribedEventNotFound handles this case with default header values.

Not Found
*/
type DeleteSubscribedEventNotFound struct {
}

func (o *DeleteSubscribedEventNotFound) Error() string {
	return fmt.Sprintf("[DELETE /cobrand/config/notifications/events/{eventName}][%d] deleteSubscribedEventNotFound ", 404)
}

func (o *DeleteSubscribedEventNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
