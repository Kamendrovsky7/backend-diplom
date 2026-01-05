import yaml
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction
from django.apps import apps
from auto_app.models import (
    Supplier,
    Category,
    Product,
    ProductAttribute,
    ProductAttributeValue,
)


class Command(BaseCommand):
    help = "Загружает данные из YML файла в базу данных"

    def add_arguments(self, parser):
        parser.add_argument("yaml_file", type=str, help="Путь к YML файлу с данными")

    def handle(self, *args, **options):
        yaml_file_path = options["yaml_file"]
        self.stdout.write(f"Загрузку данных из файла: {yaml_file_path}")

        try:
            with open(yaml_file_path, "r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except FileNotFoundError:
            raise CommandError(f'Файл "{yaml_file_path}" не найден.')
        except yaml.YAMLError as e:
            raise CommandError(f'Ошибка при парсинге YML файла "{yaml_file_path}": {e}')

        if not data:
            self.stdout.write(
                self.style.WARNING("YML-файл пуст или не содержит данных.")
            )
            return

        with transaction.atomic():
            self._process_supplier(data)
            self._process_categories(data)
            self._process_products(data)

        self.stdout.write(self.style.SUCCESS("Загрузка данных успешна."))

    def _process_supplier(self, data):
        shop_name = data.get("shop")
        if not shop_name:
            self.stderr.write(
                self.style.ERROR(
                    "В YML файле не указано поле 'shop' для определения поставщика."
                )
            )
            return

        try:
            supplier, created = Supplier.objects.get_or_create(name=shop_name)
            if created:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Создан или найден поставщик: '{supplier.name}'"
                    )
                )
            else:
                self.stdout.write(f"Такой поставщик '{supplier.name}' уже существует.")
            self.current_supplier = supplier
        except IntegrityError:
            self.stderr.write(
                self.style.ERROR(
                    f"Ошибка целостности данных для поставщика '{shop_name}'.Скорее всего, копия."
                )
            )
            raise CommandError("Ошибка обработки данных поставщика.")

    def _process_categories(self, data):
        categories_data = data.get("categories", [])
        self.stdout.write(f"Найдено {len(categories_data)} категорий для загрузки.")

        for cat_data in categories_data:
            try:
                Category.objects.get_or_create(
                    external_id=cat_data["id"], defaults={"name": cat_data["name"]}
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Категория '{cat_data['name']}' (ID: {cat_data['id']}) успешно обработана."
                    )
                )
            except KeyError as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Ошибка в данных категории: отсутствует поле {e} в записи: {cat_data}"
                    )
                )
            except IntegrityError:
                self.stderr.write(
                    self.style.ERROR(
                        f"Ошибка целостности данных для категории с ID {cat_data.get('id')}. Скорее всего, копия."
                    )
                )

    def _process_products(self, data):
        products_data = data.get("goods", [])
        self.stdout.write(f"Найдено {len(products_data)} товаров для загрузки.")

        current_supplier = getattr(self, "current_supplier", None)
        if not current_supplier:
            self.stderr.write(
                self.style.ERROR(
                    "Поставщик не был определен. Пропуск загрузки товаров."
                )
            )
            return

        for prod_data in products_data:
            try:
                product_sku = prod_data.get("sku")
                product_name = prod_data["name"]  # Обязательное поле

                category_id = prod_data.get("category")
                category = None
                if category_id:
                    category = Category.objects.filter(external_id=category_id).first()
                    if not category:
                        self.stderr.write(
                            self.style.WARNING(
                                f"Категория с ID {category_id} для товара '{product_name}' не найдена. "
                                f"Товар будет создан без категории."
                            )
                        )

                parameters_data = prod_data.get("parameters", {})
                product_parameters_list = []
                for attr_name, attr_value in parameters_data.items():
                    if not attr_name or attr_value is None:
                        continue

                    attribute, attr_created = ProductAttribute.objects.get_or_create(
                        name=attr_name
                    )
                    if attr_created:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Создан новый параМетр товара: '{attribute.name}'"
                            )
                        )

                    product_parameters_list.append((attribute, str(attr_value)))

                product = None
                if product_sku:
                    product, created = Product.objects.get_or_create(
                        sku=product_sku,
                        defaults={
                            "name": product_name,
                            "description": prod_data.get("description"),
                            "price": prod_data["price"],
                            "supplier": current_supplier,
                            "category": category,
                            "stock_quantity": prod_data.get("quantity", 0),
                        },
                    )
                    if created:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Создан товар по SKU: '{product.name}' (SKU: {product.sku})"
                            )
                        )
                    else:
                        product.name = product_name
                        product.description = prod_data.get("description")
                        product.price = prod_data["price"]
                        product.supplier = current_supplier
                        product.category = category
                        product.stock_quantity = prod_data.get("quantity", 0)
                        product.save()
                        self.stdout.write(
                            f"Обновлен товар по SKU: '{product.name}' (SKU: {product.sku})"
                        )
                else:
                    existing_product = Product.objects.filter(
                        name=product_name, supplier=current_supplier, category=category
                    ).first()

                    if existing_product:
                        product = existing_product
                        product.description = prod_data.get("description")
                        product.price = prod_data["price"]
                        product.stock_quantity = prod_data.get("quantity", 0)
                        if product.supplier != current_supplier:
                            product.supplier = current_supplier
                        if product.category != category:
                            product.category = category
                        product.save()
                        self.stdout.write(
                            f"Обновлен товар (найден по имени/категории/поставщику): '{product.name}'"
                        )
                    else:
                        product = Product.objects.create(
                            name=product_name,
                            description=prod_data.get("description"),
                            price=prod_data["price"],
                            supplier=current_supplier,
                            category=category,
                            sku=None,
                            stock_quantity=prod_data.get("quantity", 0),
                        )
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Создан новый товар: '{product.name}' (без SKU)"
                            )
                        )

                if product:
                    ProductAttributeValue.objects.filter(product=product).exclude(
                        attribute__name__in=[
                            attr[0].name for attr in product_parameters_list
                        ]
                    ).delete()

                    for attribute, value_str in product_parameters_list:
                        ProductAttributeValue.objects.update_or_create(
                            product=product,
                            attribute=attribute,
                            defaults={"value": value_str},
                        )
                else:
                    self.stderr.write(
                        self.style.ERROR(
                            f"Не удалось получить или создать объект Product для товара: {product_name}."
                        )
                    )

            except KeyError as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Ошибка в данных товара: отсутствует обязательное поле {e} в записи: {prod_data}"
                    )
                )
            except IntegrityError as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Ошибка целостности данных для товара '{prod_data.get('name')}': {e}. Скорее всего, копия SKU."
                    )
                )
            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Непредвиденная ошибка при обработке товара '{prod_data.get('name')}': {e}"
                    )
                )
