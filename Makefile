.PHONY: seed run

seed:
	python backend/scripts/seed_data.py

run:
	streamlit run app.py
