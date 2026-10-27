# Rails controller fixture (source only, intentionally mixed). Not run.
class OrdersController < ApplicationController
  before_action :authenticate_user!

  # IDOR: finds by id across all orders, not scoped to the user
  def show
    @order = Order.find(params[:id])
    render json: @order
  end

  # safe: scoped to the signed-in user
  def receipt
    @order = current_user.orders.find(params[:id])
    render json: @order
  end

  # SQL injection via string interpolation
  def search
    @orders = Order.where("item LIKE '%#{params[:q]}%'")
    render json: @orders
  end

  # BFLA: admin action with no role check (only authenticated)
  def ship
    Order.find(params[:id]).update(status: 'shipped')
    head :ok
  end
end
