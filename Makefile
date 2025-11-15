.PHONY: help build up down restart logs clean backup restore stats test

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m # No Color

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo '${GREEN}Network Monitor with Vallanx - Docker Commands${NC}'
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${NC} ${GREEN}<target>${NC}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  ${YELLOW}%-20s${NC} %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Initialize project (first time setup)
	@echo "${GREEN}Initializing project...${NC}"
	@cp -n .env.example .env || true
	@mkdir -p config volumes/{logs,data,backups}
	@echo "${GREEN}✓ Project initialized${NC}"
	@echo "${YELLOW}Please edit .env file with your configuration${NC}"

build: ## Build Docker images
	@echo "${GREEN}Building Docker images...${NC}"
	docker-compose build --no-cache
	@echo "${GREEN}✓ Build completed${NC}"

up: ## Start all services
	@echo "${GREEN}Starting services...${NC}"
	docker-compose up -d
	@echo "${GREEN}✓ Services started${NC}"
	@make status

down: ## Stop all services
	@echo "${YELLOW}Stopping services...${NC}"
	docker-compose down
	@echo "${GREEN}✓ Services stopped${NC}"

restart: ## Restart all services
	@echo "${YELLOW}Restarting services...${NC}"
	docker-compose restart
	@echo "${GREEN}✓ Services restarted${NC}"

start: up ## Alias for 'up'

stop: down ## Alias for 'down'

logs: ## Show logs from all services
	docker-compose logs -f

logs-monitor: ## Show logs from network-monitor service only
	docker-compose logs -f network-monitor

logs-mysql: ## Show logs from MySQL service
	docker-compose logs -f mysql

status: ## Show status of all services
	@echo "${GREEN}Service Status:${NC}"
	@docker-compose ps

ps: status ## Alias for 'status'

stats: ## Show container resource usage
	@echo "${GREEN}Container Statistics:${NC}"
	@docker stats --no-stream

shell: ## Open shell in network-monitor container
	docker-compose exec network-monitor bash

shell-mysql: ## Open MySQL shell
	docker-compose exec mysql mysql -u monitor_user -p

clean: ## Remove all containers and volumes (WARNING: deletes all data!)
	@echo "${RED}WARNING: This will delete all data!${NC}"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose down -v; \
		rm -rf volumes/*; \
		echo "${GREEN}✓ Cleanup completed${NC}"; \
	else \
		echo "${YELLOW}Cancelled${NC}"; \
	fi

clean-containers: ## Remove only containers (keep volumes)
	docker-compose down
	@echo "${GREEN}✓ Containers removed${NC}"

backup: ## Create backup of database and config
	@echo "${GREEN}Creating backup...${NC}"
	@mkdir -p backups/$$(date +%Y%m%d_%H%M%S)
	@docker-compose exec -T mysql mysqldump -u root -p$${MYSQL_ROOT_PASSWORD} \
		--all-databases > backups/$$(date +%Y%m%d_%H%M%S)/database.sql
	@docker cp network-monitor:/etc/vallanx backups/$$(date +%Y%m%d_%H%M%S)/
	@cp -r config backups/$$(date +%Y%m%d_%H%M%S)/
	@cp .env backups/$$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
	@echo "${GREEN}✓ Backup created in backups/$$(date +%Y%m%d_%H%M%S)/${NC}"

restore: ## Restore from backup (requires BACKUP_DIR variable)
	@if [ -z "$(BACKUP_DIR)" ]; then \
		echo "${RED}Error: BACKUP_DIR not specified${NC}"; \
		echo "Usage: make restore BACKUP_DIR=backups/20240101_120000"; \
		exit 1; \
	fi
	@echo "${YELLOW}Restoring from $(BACKUP_DIR)...${NC}"
	@docker-compose stop
	@docker-compose exec -T mysql mysql -u root -p$${MYSQL_ROOT_PASSWORD} \
		< $(BACKUP_DIR)/database.sql
	@docker cp $(BACKUP_DIR)/vallanx network-monitor:/etc/
	@docker-compose start
	@echo "${GREEN}✓ Restore completed${NC}"

update: ## Update to latest version
	@echo "${GREEN}Updating...${NC}"
	@make backup
	git pull
	docker-compose build --no-cache
	docker-compose down
	docker-compose up -d
	@echo "${GREEN}✓ Update completed${NC}"

test: ## Run tests
	@echo "${GREEN}Running tests...${NC}"
	docker-compose exec network-monitor python3 -m pytest tests/

vallanx-stats: ## Show Vallanx blocklist statistics
	@echo "${GREEN}Vallanx Statistics:${NC}"
	@docker-compose exec network-monitor python3 -c "from vallanx_blocklist_manager import VallanxBlocklistManager; vm = VallanxBlocklistManager('/etc/vallanx'); import json; print(json.dumps(vm.get_statistics(), indent=2))"

vallanx-export: ## Export Vallanx blocklists (all formats)
	@echo "${GREEN}Exporting Vallanx blocklists...${NC}"
	@mkdir -p exports/$$(date +%Y%m%d)
	@curl -s http://localhost:8089/api/vallanx/export/suricata > exports/$$(date +%Y%m%d)/vallanx.rules
	@curl -s http://localhost:8089/api/vallanx/export/iptables > exports/$$(date +%Y%m%d)/vallanx-iptables.sh
	@curl -s http://localhost:8089/api/vallanx/export/nginx > exports/$$(date +%Y%m%d)/vallanx-nginx.conf
	@curl -s http://localhost:8089/api/vallanx/export/json > exports/$$(date +%Y%m%d)/vallanx.json
	@echo "${GREEN}✓ Exports saved to exports/$$(date +%Y%m%d)/${NC}"

db-optimize: ## Optimize database tables
	@echo "${GREEN}Optimizing database...${NC}"
	@docker-compose exec mysql mysql -u root -p$${MYSQL_ROOT_PASSWORD} -e "CALL network_monitor.sp_cleanup_old_data(30);"
	@docker-compose exec mysql mysql -u root -p$${MYSQL_ROOT_PASSWORD} -e "OPTIMIZE TABLE network_monitor.traffic_stats, network_monitor.suricata_alerts, network_monitor.connection_logs;"
	@echo "${GREEN}✓ Database optimized${NC}"

db-size: ## Show database size
	@echo "${GREEN}Database Size:${NC}"
	@docker-compose exec mysql mysql -u root -p$${MYSQL_ROOT_PASSWORD} -e "SELECT table_name, ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)' FROM information_schema.tables WHERE table_schema = 'network_monitor' ORDER BY (data_length + index_length) DESC;"

health: ## Check health of all services
	@echo "${GREEN}Health Check:${NC}"
	@echo ""
	@echo "Network Monitor:"
	@curl -f http://localhost:5000/api/stats >/dev/null 2>&1 && echo "  ${GREEN}✓${NC} Web Interface: OK" || echo "  ${RED}✗${NC} Web Interface: FAILED"
	@curl -f http://localhost:8089/api/vallanx/stats >/dev/null 2>&1 && echo "  ${GREEN}✓${NC} Vallanx API: OK" || echo "  ${RED}✗${NC} Vallanx API: FAILED"
	@echo ""
	@echo "Database:"
	@docker-compose exec mysql mysqladmin ping -h localhost -u root -p$${MYSQL_ROOT_PASSWORD} >/dev/null 2>&1 && echo "  ${GREEN}✓${NC} MySQL: OK" || echo "  ${RED}✗${NC} MySQL: FAILED"

install: init build up ## Complete installation (init + build + up)
	@echo ""
	@echo "${GREEN}========================================${NC}"
	@echo "${GREEN}Installation completed!${NC}"
	@echo "${GREEN}========================================${NC}"
	@echo ""
	@echo "Access the application:"
	@echo "  Web Interface: ${YELLOW}http://localhost:5000${NC}"
	@echo "  Vallanx API:   ${YELLOW}http://localhost:8089${NC}"
	@echo ""
	@echo "Useful commands:"
	@echo "  ${YELLOW}make logs${NC}        - View logs"
	@echo "  ${YELLOW}make status${NC}      - Check status"
	@echo "  ${YELLOW}make health${NC}      - Health check"
	@echo "  ${YELLOW}make help${NC}        - Show all commands"
	@echo ""

with-nginx: ## Start with Nginx reverse proxy
	docker-compose --profile nginx up -d
	@echo "${GREEN}✓ Started with Nginx on port 80${NC}"

with-grafana: ## Start with Grafana monitoring
	docker-compose --profile monitoring up -d
	@echo "${GREEN}✓ Started with Grafana on port 3000${NC}"

with-all: ## Start with all optional services
	docker-compose --profile nginx --profile monitoring --profile cache up -d
	@echo "${GREEN}✓ Started with all services${NC}"

prune: ## Remove unused Docker resources
	@echo "${YELLOW}Cleaning up Docker resources...${NC}"
	docker system prune -f
	@echo "${GREEN}✓ Cleanup completed${NC}"

version: ## Show version information
	@echo "${GREEN}Network Monitor with Vallanx${NC}"
	@echo "Version: 1.0.0"
	@echo ""
	@echo "Docker:"
	@docker --version
	@docker-compose --version
