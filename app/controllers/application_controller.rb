class ApplicationController < ActionController::API
  def authenticate
    render json: {status: 401, message: "unauthorized"} unless decode_token(bearer_token)
  end

  def bearer_token
    pattern = /^Bearer /
    header  = request.env["HTTP_AUTHORIZATION"] # <= env
    header.gsub(pattern, '') if header && header.match(pattern)
  end

  def current_user
    return if !bearer_token
    decoded_jwt = decode_token(bearer_token)

    User.find(decoded_jwt['user']['id'])
  end

  def decode_token(token)
    token = JWT.decode(token, nil, false) # Colin suggested we add [0] to the end of this line, but that may have been the cause of some of our bugs so we removed it.
  rescue
    render json: {status: 401, message: 'invalid or expired token'}
  end

end
