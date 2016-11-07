class CheerUpsController < ApplicationController
  # GET /cheer_ups
  def index
    cheer_ups = CheerUp.all

    render json: {status: 200, cheer_ups: cheer_ups}
  end
  # GET /cheer_ups/:id
  def show
    cheer_up = CheerUp.find(params[:id])
    render json: {status: 200, cheer_up: cheer_up}
  end

  # POST /cheer_ups/:id/add_review
  def add_review
    cheer_up = CheerUp.find(params[:id])
    review = cheer_up.reviews.new(review_params)
    review.user_id = current_user.id
    if review.save
      render json:
      {
        status: 200,
        cheer_up: cheer_up,
        review: cheer_up.reviews
      }
    else
      render json:
      {
        status: 400,
        cheer_up: cheer_up,
        review: review.errors
      }
    end
  end

  private
    def cheer_up_params
        params.require(:cheer_up).permit(:title, :content, :category, :user_id)
    end

    def review_params
      params.require(:review).permit(:value, :cheer_up_id, :user_id)
    end

end
