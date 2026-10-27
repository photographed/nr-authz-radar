# Django REST Framework fixture (source only). Not run.
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import pickle


class OrderView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id):
        # IDOR: get by pk, no owner filter
        order = Order.objects.get(pk=order_id)
        return Response(order.data)


class ImportView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # unsafe deserialization
        data = pickle.loads(request.body)
        return Response({"ok": True})
